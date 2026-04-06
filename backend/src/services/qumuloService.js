'use strict';

const http = require('http');

/**
 * Call the Qumulo proxy to make a request to a Qumulo cluster.
 */
async function qumuloRequest(cluster, method, apiPath, body = null, bearerToken = null) {
  const scheme = cluster.use_ssl ? 'https' : 'http';
  const target = `${scheme}://${cluster.host}:${cluster.port}`;

  const headers = {};
  if (bearerToken) {
    headers['Authorization'] = `Bearer ${bearerToken}`;
  }

  return new Promise((resolve, reject) => {
    const payload = JSON.stringify({ method, path: apiPath, body, headers });

    const options = {
      hostname: '127.0.0.1',
      port: 3007,
      path: '/proxy',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload),
        'X-Proxy-Target': target,
      },
    };

    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', (c) => (data += c));
      res.on('end', () => {
        try {
          const parsed = JSON.parse(data);
          if (res.statusCode >= 200 && res.statusCode < 300) {
            resolve(parsed);
          } else {
            reject(Object.assign(
              new Error(parsed.error_description || parsed.description || parsed.error || 'Qumulo API error'),
              { statusCode: res.statusCode, body: parsed }
            ));
          }
        } catch {
          reject(new Error(`Non-JSON response from cluster: ${data.slice(0, 200)}`));
        }
      });
    });

    req.on('error', reject);
    req.setTimeout(30000, () => { req.destroy(); reject(new Error('Request timeout')); });
    req.write(payload);
    req.end();
  });
}

/**
 * Login to a Qumulo cluster and get a session token.
 */
async function qumuloLogin(cluster) {
  const result = await qumuloRequest(cluster, 'POST', '/v1/session/login', {
    username: cluster.api_username,
    password: cluster.api_password,
  });
  return result.bearer_token;
}

/**
 * Try v2 first, fall back to v1 on 404.
 */
async function qumuloRequestVersioned(cluster, method, path, body, token) {
  const v2Path = path.replace(/^\/v1\//, '/v2/');
  try {
    return await qumuloRequest(cluster, method, v2Path, body, token);
  } catch (err) {
    if (err.statusCode === 404) {
      return await qumuloRequest(cluster, method, path, body, token);
    }
    throw err;
  }
}

/**
 * Normalize API response to a plain array.
 */
function toArray(val) {
  if (!val) return [];
  if (Array.isArray(val)) return val;
  if (Array.isArray(val.entries)) return val.entries;
  const found = Object.values(val).find(v => Array.isArray(v));
  return found || [];
}

/**
 * Get all replication source relationships from a cluster.
 */
async function getSourceRelationships(cluster) {
  const token = await qumuloLogin(cluster);
  return qumuloRequestVersioned(cluster, 'GET', '/v1/replication/source-relationships/', null, token);
}

/**
 * Get all replication target relationships from a cluster.
 */
async function getTargetRelationships(cluster) {
  const token = await qumuloLogin(cluster);
  return qumuloRequestVersioned(cluster, 'GET', '/v1/replication/target-relationships/', null, token);
}

/**
 * Get ALL source relationship statuses in a single API call.
 * Returns a Map of { qumuloId -> statusObject }.
 */
async function getAllSourceStatuses(cluster, token) {
  const raw = await qumuloRequestVersioned(
    cluster, 'GET', '/v1/replication/source-relationships/status/', null, token
  );
  const arr = toArray(raw);
  return new Map(arr.map(s => [s.id, s]));
}

/**
 * Get ALL target relationship statuses in a single API call.
 * Returns a Map of { qumuloId -> statusObject }.
 */
async function getAllTargetStatuses(cluster, token) {
  const raw = await qumuloRequestVersioned(
    cluster, 'GET', '/v1/replication/target-relationships/status/', null, token
  );
  const arr = toArray(raw);
  return new Map(arr.map(s => [s.id, s]));
}

/**
 * Get status for a specific source relationship (used during discovery).
 */
async function getSourceRelationshipStatus(cluster, relationshipId) {
  const token = await qumuloLogin(cluster);
  return qumuloRequestVersioned(cluster, 'GET', `/v1/replication/source-relationships/${relationshipId}/status`, null, token);
}

/**
 * Get status for a specific target relationship (used during discovery).
 */
async function getTargetRelationshipStatus(cluster, relationshipId) {
  const token = await qumuloLogin(cluster);
  return qumuloRequestVersioned(cluster, 'GET', `/v1/replication/target-relationships/${relationshipId}/status`, null, token);
}

/**
 * Test connectivity to a cluster (login and logout).
 */
async function testClusterConnection(cluster) {
  try {
    const token = await qumuloLogin(cluster);
    await qumuloRequest(cluster, 'POST', '/v1/session/logout', {}, token).catch(() => {});
    return { success: true };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

module.exports = {
  qumuloLogin,
  getSourceRelationships,
  getTargetRelationships,
  getAllSourceStatuses,
  getAllTargetStatuses,
  getSourceRelationshipStatus,
  getTargetRelationshipStatus,
  testClusterConnection,
};
