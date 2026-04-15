import { FastifyInstance, FastifyPluginAsync } from 'fastify';
import { PythonBridge } from '../services/python-bridge.js';

const bridge = new PythonBridge();

export const timelineRoutes: FastifyPluginAsync = async (app: FastifyInstance) => {
  // Get timeline for a case
  app.get<{ Params: { caseId: string } }>('/:caseId', async (req, reply) => {
    const { caseId } = req.params;
    const result = await bridge.run(`timeline generate --case ${caseId}`);
    return reply.send(result);
  });

  // Export timeline
  app.get<{ Params: { caseId: string }; Querystring: { format?: string } }>('/:caseId/export', async (req, reply) => {
    const { caseId } = req.params;
    const { format = 'csv' } = req.query;
    const result = await bridge.run(`timeline export --case ${caseId} --format ${format}`);
    return reply.send(result);
  });

  // Filter timeline
  app.post<{ Params: { caseId: string } }>('/:caseId/filter', async (req, reply) => {
    const { caseId } = req.params;
    const { from, to, source } = req.body as any;
    let cmd = `timeline filter --case ${caseId}`;
    if (from) cmd += ` --from "${from}"`;
    if (to) cmd += ` --to "${to}"`;
    if (source) cmd += ` --source "${source}"`;
    const result = await bridge.run(cmd);
    return reply.send(result);
  });
};