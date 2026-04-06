/**
 * Qumulo HTTPS Proxy
 * Handles API requests to Qumulo clusters that use self-signed certificates.
 * Runs on port 3007. Only accessible from localhost (backend).
 *
 * Request format:
 *   POST /proxy
 *   Headers: X-Proxy-Target: https://qumulo-cluster-host:8000
 *   Body: { method, path, body, headers }
 */

'use strict';

process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'; // Allow self-signed certs

const express = require('express');
const https = require('https');
const http = require('http');
const cors = require('cors');

const app = express();
const PORT = process.env.PROXY_PORT || 3007;

app.use(cors({ origin: 'http://localhost:3006' }));
app.use(express.json({ limit: '10mb' }));

// Health check
app.get('/health', (req, res) => res.json({ status: 'ok', service: 'qumulo-proxy' }));

/**
 * Main proxy endpoint
 * Backend sends requests here; proxy forwards to Qumulo cluster.
 */
app.post('/proxy', async (req, res) => {
  const target = req.headers['x-proxy-target'];
  if (!target) {
    return res.status(400).json({ error: 'Missing X-Proxy-Target header' });
  }

  const { method = 'GET', path: apiPath = '/', body, headers = {} } = req.body;

  let targetUrl;
  try {
    targetUrl = new URL(apiPath, target);
  } catch (e) {
    return res.status(400).json({ error: `Invalid target URL: ${target}${apiPath}` });
  }

  const isHttps = targetUrl.protocol === 'https:';
  const transport = isHttps ? https : http;

  // Only serialize a body for methods that carry one and when body is provided
  const hasBody = body !== null && body !== undefined && method.toUpperCase() !== 'GET';
  const bodyStr = hasBody ? JSON.stringify(body) : null;

  const reqHeaders = {
    Accept: 'application/json',
    ...headers,
  };

  if (bodyStr) {
    // Only set Content-Type when we actually have a body — Qumulo's JSON
    // parser will throw a 400 json_decode_error if Content-Type is
    // application/json but the body is empty.
    reqHeaders['Content-Type'] = 'application/json';
    reqHeaders['Content-Length'] = Buffer.byteLength(bodyStr);
  } else {
    reqHeaders['Content-Length'] = 0;
  }

  const options = {
    hostname: targetUrl.hostname,
    port: targetUrl.port || (isHttps ? 443 : 80),
    path: targetUrl.pathname + targetUrl.search,
    method: method.toUpperCase(),
    headers: reqHeaders,
    rejectUnauthorized: false, // KEY: allow self-signed certs
    timeout: 15000,
  };

  const proxyReq = transport.request(options, (proxyRes) => {
    let data = '';
    proxyRes.on('data', (chunk) => (data += chunk));
    proxyRes.on('end', () => {
      res.status(proxyRes.statusCode);
      // Forward relevant response headers
      const fwdHeaders = ['content-type', 'x-qumulo-request-id'];
      fwdHeaders.forEach((h) => {
        if (proxyRes.headers[h]) res.set(h, proxyRes.headers[h]);
      });
      try {
        res.json(JSON.parse(data));
      } catch {
        res.send(data);
      }
    });
  });

  proxyReq.on('error', (err) => {
    console.error(`[Proxy] Error reaching ${targetUrl.href}:`, err.message);
    res.status(502).json({ error: 'Proxy connection failed', detail: err.message });
  });

  proxyReq.on('timeout', () => {
    proxyReq.destroy();
    res.status(504).json({ error: 'Proxy request timed out' });
  });

  if (bodyStr) proxyReq.write(bodyStr);
  proxyReq.end();
});

app.listen(PORT, '127.0.0.1', () => {
  console.log(`[Qumulo Proxy] Listening on http://127.0.0.1:${PORT}`);
  console.log(`[Qumulo Proxy] SSL certificate validation DISABLED for Qumulo targets`);
});
