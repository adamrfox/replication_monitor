'use strict';

const cron = require('node-cron');
const { v4: uuidv4 } = require('uuid');
const { getDb } = require('../db/database');
const {
  qumuloLogin,
  getAllSourceStatuses,
  getAllTargetStatuses,
} = require('./qumuloService');
const { sendAlertEmail, logAlert, shouldSendAlert } = require('./alertService');

let cronJob = null;
let isPolling = false;

function getSettings() {
  const db = getDb();
  const rows = db.prepare('SELECT key, value FROM settings').all();
  return Object.fromEntries(rows.map((r) => [r.key, r.value]));
}

/**
 * Extract lag in seconds from a Qumulo v2 status response.
 * Uses recovery_point (last successful replication timestamp).
 * Falls back to last_replication_completion_time for v1.
 */
function extractLagSeconds(data) {
  if (!data) return null;

  // v2: recovery_point is the last successful replication time
  const rp = data.recovery_point || data.last_replication_completion_time;
  if (rp && rp !== '') {
    const last = new Date(rp);
    if (!isNaN(last.getTime())) {
      return Math.round((Date.now() - last.getTime()) / 1000);
    }
  }

  // v1 fallback
  if (typeof data.estimated_time_to_completion === 'number') {
    return data.estimated_time_to_completion;
  }

  return null;
}

/**
 * Extract a normalized status string from a Qumulo status response.
 *
 * v2 job_state values:
 *   REPLICATION_NOT_RUNNING, REPLICATION_RUNNING, REPLICATION_QUEUED,
 *   REPLICATION_ERROR, REPLICATION_DISABLED
 *
 * v2 state values:
 *   ESTABLISHED, RECOVERING, ERROR, DISABLED
 */
function extractStatus(data) {
  if (!data) return 'unknown';

  const jobState = (data.job_state || '').toLowerCase();
  const state    = (data.state    || '').toLowerCase();

  // Ended — relationship permanently terminated
  if (data.end_reason && data.end_reason !== '') return 'ended';

  // Disabled on cluster
  if (data.replication_enabled === false) return 'disabled';
  if (jobState.includes('disabled') || state.includes('disabled')) return 'disabled';

  // Disconnected — cannot reach target cluster
  if (state === 'disconnected') return 'error';

  // Awaiting authorization
  if (state === 'awaiting_authorization') return 'unknown';

  // Error — job faulted or cannot reach target
  if (jobState.includes('error') || state.includes('error')) return 'error';

  // Active transfer — job_state is exactly REPLICATION_RUNNING
  if (jobState === 'replication_running') return 'running';

  // OK — established and idle
  if (state === 'established') return 'ok';
  if (jobState === 'replication_not_running' || jobState === 'replication_queued') return 'ok';

  // Generic fallbacks
  const combined = jobState + ' ' + state;
  if (combined.includes('fail') || combined.includes('error')) return 'error';
  if (combined.includes('disconnect')) return 'error';
  if (combined.includes('ok') || combined.includes('success') || combined.includes('complete') || combined.includes('established')) return 'ok';

  return 'unknown';
}

/**
 * Update stored source_root_path / target details from status if we didn't
 * get them during discovery (v2 relationships list doesn't include paths).
 */
function updateRelationshipPaths(db, relId, statusData) {
  if (!statusData) return;
  const sourcePath   = statusData.source_root_path || null;
  const targetPath   = statusData.target_root_path || null;
  const targetHost   = statusData.target_address   || null;
  const replMode     = statusData.replication_mode || null;
  // replication_enabled comes from the API — always update it so we stay current
  const replEnabled  = typeof statusData.replication_enabled === 'boolean'
    ? (statusData.replication_enabled ? 1 : 0)
    : null;
  // Store end_reason — use null if empty string so we can distinguish "ended" from "unknown"
  const endReason = statusData.end_reason && statusData.end_reason !== ''
    ? statusData.end_reason
    : null;

  db.prepare(`
    UPDATE replication_relationships SET
      source_path         = COALESCE(NULLIF(source_path, ''),      ?),
      target_path         = COALESCE(NULLIF(target_path, ''),      ?),
      target_host         = COALESCE(NULLIF(target_host, ''),      ?),
      replication_mode    = COALESCE(NULLIF(replication_mode, ''), ?),
      replication_enabled = COALESCE(?, replication_enabled),
      end_reason          = ?,
      display_name        = COALESCE(NULLIF(display_name, ''),     ?),
      updated_at          = CURRENT_TIMESTAMP
    WHERE id = ?
  `).run(
    sourcePath,
    targetPath,
    targetHost,
    replMode,
    replEnabled,
    endReason,
    statusData.source_cluster_name && sourcePath
      ? (statusData.source_cluster_name + ':' + sourcePath + ' → ' + (statusData.target_cluster_name || targetHost) + ':' + (targetPath || ''))
      : null,
    relId
  );
}

async function pollAll() {
  if (isPolling) {
    console.log('[Poller] Still running, skipping this cycle.');
    return;
  }
  isPolling = true;
  const db = getDb();
  const settings = getSettings();
  const defaultLagThreshold = parseInt(settings.default_lag_threshold_minutes) || 60;
  const defaultSnapshotQueueThreshold = parseInt(settings.default_snapshot_queue_threshold) || 3;
  const cooldownMinutes = parseInt(settings.alert_cooldown_minutes) || 30;

  // Clean up old alert log entries based on retention setting
  const retentionDays = parseInt(settings.alert_retention_days) || 90;
  if (retentionDays > 0) {
    const cutoff = new Date(Date.now() - retentionDays * 24 * 60 * 60 * 1000).toISOString();
    const deleted = db.prepare('DELETE FROM alert_log WHERE sent_at < ?').run(cutoff);
    if (deleted.changes > 0) {
      console.log(`[Poller] Pruned ${deleted.changes} alert log entries older than ${retentionDays} days`);
    }
  }

  const clusters = db.prepare('SELECT * FROM clusters').all();

  for (const cluster of clusters) {
    let token;
    try {
      token = await qumuloLogin(cluster);
    } catch (err) {
      console.error(`[Poller] Cannot login to cluster ${cluster.name}: ${err.message}`);
      continue;
    }

    const relationships = db.prepare(
      `SELECT * FROM replication_relationships WHERE cluster_id = ? AND enabled = 1`
    ).all(cluster.id);

    // Fetch all statuses in bulk — 2 API calls per cluster regardless of relationship count
    const [sourceStatuses, targetStatuses] = await Promise.all([
      getAllSourceStatuses(cluster, token).catch(err => {
        console.error(`[Poller] Bulk source status failed for ${cluster.name}: ${err.message}`);
        return new Map();
      }),
      getAllTargetStatuses(cluster, token).catch(err => {
        console.error(`[Poller] Bulk target status failed for ${cluster.name}: ${err.message}`);
        return new Map();
      }),
    ]);

    for (const rel of relationships) {
      try {
        const statusMap = rel.direction === 'target' ? targetStatuses : sourceStatuses;
        const statusData = statusMap.get(rel.qumulo_id);

        if (!statusData) {
          // Relationship not found in bulk response — log as error
          const errMsg = `Relationship ${rel.qumulo_id} not found in cluster status response`;
          db.prepare(`
            INSERT INTO poll_results(id, cluster_id, relationship_id, status, error_message, polled_at)
            VALUES (?, ?, ?, 'error', ?, ?)
          `).run(uuidv4(), cluster.id, rel.id, errMsg, new Date().toISOString());
          continue;
        }

        // Backfill paths from status if not already stored
        updateRelationshipPaths(db, rel.id, statusData);

        const replMode = statusData.replication_mode || rel.replication_mode || '';
        const isSnapshot = replMode === 'REPLICATION_SNAPSHOT_POLICY'; // hybrid uses continuous lag logic
        const isDisabled = statusData.replication_enabled === false;
        const lagSeconds = isSnapshot && !isDisabled
          // Active snapshot rel: store queue depth so UI can show count vs threshold
          ? (statusData.queued_snapshot_count ?? 0)
          // Disabled snapshot rel or continuous rel: store time-based lag from recovery_point
          // A disabled snapshot rel with a 2-year-old recovery_point should still surface that lag
          : extractLagSeconds(statusData);
        const jobStatus  = extractStatus(statusData);
        const errorMsg   = statusData.error_from_last_job || null;

        db.prepare(`
          INSERT INTO poll_results(id, cluster_id, relationship_id, status, lag_seconds, error_message, raw_data, polled_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `).run(uuidv4(), cluster.id, rel.id, jobStatus, lagSeconds, errorMsg, JSON.stringify(statusData), new Date().toISOString());

        // Trim old poll results
        db.prepare(`
          DELETE FROM poll_results WHERE relationship_id = ? AND id NOT IN (
            SELECT id FROM poll_results WHERE relationship_id = ? ORDER BY polled_at DESC LIMIT 500
          )
        `).run(rel.id, rel.id);

        const lagThresholdMin = rel.lag_threshold_minutes ?? defaultLagThreshold;
        const snapshotQueueThreshold = rel.snapshot_queue_threshold ?? defaultSnapshotQueueThreshold;
        const name = rel.display_name || rel.qumulo_id;
        const queuedSnapshots = statusData.queued_snapshot_count || 0;

        // Error state alert
        if (jobStatus === 'error') {
          if (shouldSendAlert(db, rel.id, 'error', cooldownMinutes)) {
            const msg = errorMsg || 'Unknown error';
            await sendAlertEmail(
              `ERROR: Replication "${name}" on ${cluster.name}`,
              `<h2>Replication Error</h2>
               <p><strong>Cluster:</strong> ${cluster.name} (${cluster.host})</p>
               <p><strong>Relationship:</strong> ${name}</p>
               <p><strong>Source:</strong> ${statusData.source_root_path || rel.source_path || 'N/A'}</p>
               <p><strong>Target:</strong> ${statusData.target_address || rel.target_host || ''}:${statusData.target_root_path || rel.target_path || ''}</p>
               <p><strong>Error:</strong> ${msg}</p>
               <p><em>${new Date().toISOString()}</em></p>`,
              `Replication Error\nCluster: ${cluster.name}\nRelationship: ${name}\nError: ${msg}`,
              rel.alert_recipients || null
            );
            logAlert(db, { relationship_id: rel.id, cluster_id: cluster.id, alert_type: 'error', message: msg });
          }
        }

        if (isSnapshot) {
          // Snapshot-policy relationship: alert on queued snapshot count
          if (queuedSnapshots > snapshotQueueThreshold) {
            if (shouldSendAlert(db, rel.id, 'lag', cooldownMinutes)) {
              await sendAlertEmail(
                `QUEUE ALERT: Replication "${name}" has ${queuedSnapshots} queued snapshots`,
                `<h2>Replication Queue Alert</h2>
                 <p><strong>Cluster:</strong> ${cluster.name} (${cluster.host})</p>
                 <p><strong>Relationship:</strong> ${name}</p>
                 <p><strong>Queued Snapshots:</strong> ${queuedSnapshots}</p>
                 <p><strong>Threshold:</strong> ${snapshotQueueThreshold}</p>
                 <p><strong>Source:</strong> ${statusData.source_root_path || rel.source_path || 'N/A'}</p>
                 <p><em>${new Date().toISOString()}</em></p>`,
                `Replication Queue Alert\nCluster: ${cluster.name}\nRelationship: ${name}\nQueued: ${queuedSnapshots} (threshold: ${snapshotQueueThreshold})`,
              rel.alert_recipients || null
              );
              logAlert(db, { relationship_id: rel.id, cluster_id: cluster.id, alert_type: 'lag', message: `${queuedSnapshots} snapshots queued (threshold: ${snapshotQueueThreshold})` });
            }
          }
        } else {
          // Continuous relationship: alert on time lag
          if (lagSeconds !== null && lagSeconds > lagThresholdMin * 60) {
            if (shouldSendAlert(db, rel.id, 'lag', cooldownMinutes)) {
              const lagMin = Math.round(lagSeconds / 60);
              await sendAlertEmail(
                `LAG ALERT: Replication "${name}" is ${lagMin} minutes behind`,
                `<h2>Replication Lag Alert</h2>
                 <p><strong>Cluster:</strong> ${cluster.name} (${cluster.host})</p>
                 <p><strong>Relationship:</strong> ${name}</p>
                 <p><strong>Current Lag:</strong> ${lagMin} minutes</p>
                 <p><strong>Threshold:</strong> ${lagThresholdMin} minutes</p>
                 <p><strong>Last Replicated:</strong> ${statusData.recovery_point || 'Unknown'}</p>
                 <p><em>${new Date().toISOString()}</em></p>`,
                `Replication Lag\nCluster: ${cluster.name}\nRelationship: ${name}\nLag: ${lagMin}m (threshold: ${lagThresholdMin}m)`,
              rel.alert_recipients || null
              );
              logAlert(db, { relationship_id: rel.id, cluster_id: cluster.id, alert_type: 'lag', message: `${lagMin} minutes behind (threshold: ${lagThresholdMin} min)` });
            }
          }
        }

      } catch (err) {
        console.error(`[Poller] Error processing relationship ${rel.id}:`, err.message);
      }
    }
  }

  isPolling = false;
}

function startPoller() {
  const settings = getSettings();
  const intervalSeconds = Math.max(5, parseInt(settings.poll_interval_seconds) || 60);

  let cronExpr;
  if (intervalSeconds < 60) {
    cronExpr = `*/${intervalSeconds} * * * * *`;
  } else {
    const minutes = Math.round(intervalSeconds / 60);
    cronExpr = `*/${minutes} * * * *`;
  }

  if (cronJob) cronJob.stop();
  cronJob = cron.schedule(cronExpr, () => {
    pollAll().catch((e) => console.error('[Poller] Unhandled error:', e.message));
  });

  console.log(`[Poller] Started. Polling every ${intervalSeconds}s (cron: ${cronExpr})`);
  pollAll().catch((e) => console.error('[Poller] Initial poll error:', e.message));
}

function stopPoller() {
  if (cronJob) { cronJob.stop(); cronJob = null; }
}

function restartPoller() {
  stopPoller();
  startPoller();
}

module.exports = { startPoller, stopPoller, restartPoller, pollAll };
