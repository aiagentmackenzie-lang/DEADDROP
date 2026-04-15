import Fastify from 'fastify';
import cors from '@fastify/cors';
import websocket from '@fastify/websocket';
import { casesRoutes } from './routes/cases.js';
import { evidenceRoutes } from './routes/evidence.js';
import { timelineRoutes } from './routes/timeline.js';
import { artifactsRoutes } from './routes/artifacts.js';
import { huntRoutes } from './routes/hunt.js';
import { reportsRoutes } from './routes/reports.js';
import { registerWS } from './ws/events.js';

const HOST = process.env.HOST || '0.0.0.0';
const PORT = parseInt(process.env.PORT || '8080', 10);

async function main() {
  const app = Fastify({ logger: true });

  await app.register(cors, { origin: true });
  await app.register(websocket);

  // REST API routes
  app.register(casesRoutes, { prefix: '/api/cases' });
  app.register(evidenceRoutes, { prefix: '/api/evidence' });
  app.register(timelineRoutes, { prefix: '/api/timeline' });
  app.register(artifactsRoutes, { prefix: '/api/artifacts' });
  app.register(huntRoutes, { prefix: '/api/hunt' });
  app.register(reportsRoutes, { prefix: '/api/reports' });

  // WebSocket for real-time updates
  registerWS(app);

  // Health check
  app.get('/api/health', async () => ({ status: 'ok', version: '1.0.0' }));

  try {
    await app.listen({ host: HOST, port: PORT });
    console.log(`DEADDROP API Server running on http://${HOST}:${PORT}`);
  } catch (err) {
    app.log.error(err);
    process.exit(1);
  }
}

main();