// Agent Guard Runtime Proxy
// Phase 2: Inference-level protection

import { createServer } from 'http';
import { request as httpRequest } from 'http';
import { request as httpsRequest } from 'https';
import { URL } from 'url';
import { loadPolicy } from './policy.js';
import { checkEgress } from './egress.js';
import { logEvent } from './logger.js';

const DEFAULT_PORT = 18800;

export class AgentGuardProxy {
  constructor(options = {}) {
    this.port = options.port || DEFAULT_PORT;
    this.policy = options.policy || loadPolicy();
    this.server = null;
  }

  start() {
    this.server = createServer((req, res) => {
      this.handleRequest(req, res);
    });

    this.server.listen(this.port, '127.0.0.1', () => {
      console.log(`🛡 Agent Guard Proxy listening on http://127.0.0.1:${this.port}`);
    });

    return this;
  }

  stop() {
    if (this.server) {
      this.server.close();
    }
  }

  async handleRequest(clientReq, clientRes) {
    const startTime = Date.now();
    
    try {
      // Parse target URL from proxy request
      const targetUrl = new URL(clientReq.url);
      
      // Check egress policy
      const egressResult = checkEgress(targetUrl, this.policy);
      
      if (!egressResult.allowed) {
        logEvent({
          type: 'egress_blocked',
          target: targetUrl.hostname,
          reason: egressResult.reason,
          violation: true
        });

        clientRes.writeHead(403, { 'Content-Type': 'application/json' });
        clientRes.end(JSON.stringify({
          error: 'EGRESS_DENIED',
          message: `Access to ${targetUrl.hostname} blocked by security policy`,
          reason: egressResult.reason
        }));
        return;
      }

      logEvent({
        type: 'egress_allowed',
        target: targetUrl.hostname,
        violation: false
      });

      // Forward request to target
      const response = await this.forwardRequest(clientReq, targetUrl);
      
      // Log response (for intent verification later)
      const latency = Date.now() - startTime;
      logEvent({
        type: 'request_complete',
        target: targetUrl.hostname,
        status: response.statusCode,
        latency
      });

      // Forward response to client
      clientRes.writeHead(response.statusCode, response.headers);
      response.pipe(clientRes);

    } catch (err) {
      logEvent({
        type: 'proxy_error',
        error: err.message,
        violation: false
      });

      clientRes.writeHead(502, { 'Content-Type': 'application/json' });
      clientRes.end(JSON.stringify({
        error: 'PROXY_ERROR',
        message: err.message
      }));
    }
  }

  forwardRequest(clientReq, targetUrl) {
    return new Promise((resolve, reject) => {
      const requestFn = targetUrl.protocol === 'https:' ? httpsRequest : httpRequest;
      
      const options = {
        hostname: targetUrl.hostname,
        port: targetUrl.port || (targetUrl.protocol === 'https:' ? 443 : 80),
        path: targetUrl.pathname + targetUrl.search,
        method: clientReq.method,
        headers: {
          ...clientReq.headers,
          host: targetUrl.host
        }
      };

      const proxyReq = requestFn(options, (proxyRes) => {
        resolve(proxyRes);
      });

      proxyReq.on('error', reject);

      // Forward request body
      clientReq.pipe(proxyReq);
    });
  }
}

export function createProxy(options) {
  return new AgentGuardProxy(options);
}
