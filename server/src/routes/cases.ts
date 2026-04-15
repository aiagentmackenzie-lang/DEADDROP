import { FastifyInstance, FastifyPluginAsync } from 'fastify';
import { PythonBridge } from '../services/python-bridge.js';

const bridge = new PythonBridge();

export const casesRoutes: FastifyPluginAsync = async (app: FastifyInstance) => {
  // List all cases
  app.get('/', async (req, reply) => {
    const result = await bridge.run('case list');
    return reply.send({ cases: result });
  });

  // Get case details
  app.get<{ Params: { id: string } }>('/:id', async (req, reply) => {
    const { id } = req.params;
    const result = await bridge.run(`case info ${id}`);
    return reply.send(result);
  });

  // Create case
  app.post('/', async (req, reply) => {
    const { name, analyst, notes } = req.body as any;
    const result = await bridge.run(`case create --name "${name}" --analyst "${analyst || ''}"`);
    return reply.code(201).send(result);
  });

  // Close case
  app.patch<{ Params: { id: string } }>('/:id/close', async (req, reply) => {
    const { id } = req.params;
    const result = await bridge.run(`case close ${id}`);
    return reply.send(result);
  });
};