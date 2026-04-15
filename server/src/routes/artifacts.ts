import { FastifyInstance, FastifyPluginAsync } from 'fastify';
import { PythonBridge } from '../services/python-bridge.js';

const bridge = new PythonBridge();

export const artifactsRoutes: FastifyPluginAsync = async (app: FastifyInstance) => {
  // List artifacts for a case
  app.get<{ Params: { caseId: string } }>('/:caseId', async (req, reply) => {
    const { caseId } = req.params;
    const result = await bridge.run(`case info ${caseId}`);
    return reply.send(result);
  });

  // Run filesystem analysis
  app.post('/analyze/filesystem', async (req, reply) => {
    const { case_id, evidence_id } = req.body as any;
    let cmd = `analyze filesystem --case ${case_id}`;
    if (evidence_id) cmd += ` --evidence ${evidence_id}`;
    const result = await bridge.run(cmd);
    return reply.send(result);
  });

  // Run memory analysis
  app.post('/analyze/memory', async (req, reply) => {
    const { case_id, evidence_id, plugin } = req.body as any;
    let cmd = `analyze memory --case ${case_id} --plugin ${plugin || 'windows.pslist'}`;
    if (evidence_id) cmd += ` --evidence ${evidence_id}`;
    const result = await bridge.run(cmd);
    return reply.send(result);
  });

  // Run triage
  app.post('/triage', async (req, reply) => {
    const { case_id } = req.body as any;
    const result = await bridge.run(`triage run --case ${case_id}`);
    return reply.send(result);
  });
};