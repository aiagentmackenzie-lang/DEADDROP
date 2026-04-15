import { FastifyInstance, FastifyPluginAsync } from 'fastify';
import { PythonBridge } from '../services/python-bridge.js';

const bridge = new PythonBridge();

export const reportsRoutes: FastifyPluginAsync = async (app: FastifyInstance) => {
  // Generate report
  app.post('/generate', async (req, reply) => {
    const { case_id, format, output_path } = req.body as any;
    let cmd = `report generate --case ${case_id} --format ${format || 'html'}`;
    if (output_path) cmd += ` --output "${output_path}"`;
    const result = await bridge.run(cmd);
    return reply.send(result);
  });
};