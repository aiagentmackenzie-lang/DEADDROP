import { FastifyInstance, FastifyPluginAsync } from 'fastify';
import { PythonBridge } from '../services/python-bridge.js';

const bridge = new PythonBridge();

export const huntRoutes: FastifyPluginAsync = async (app: FastifyInstance) => {
  // Run YARA hunt
  app.post('/yara', async (req, reply) => {
    const { case_id, yara_rules, pack } = req.body as any;
    let cmd = `hunt run --case ${case_id}`;
    if (yara_rules) cmd += ` --yara "${yara_rules}"`;
    if (pack) cmd += ` --pack ${pack}`;
    const result = await bridge.run(cmd);
    return reply.send(result);
  });

  // Run IOC match
  app.post('/ioc', async (req, reply) => {
    const { case_id, ioc_path } = req.body as any;
    const result = await bridge.run(`hunt run --case ${case_id} --ioc "${ioc_path}"`);
    return reply.send(result);
  });

  // Get hunt results
  app.get<{ Params: { caseId: string } }>('/results/:caseId', async (req, reply) => {
    const { caseId } = req.params;
    const result = await bridge.run(`case info ${caseId}`);
    return reply.send(result);
  });
};