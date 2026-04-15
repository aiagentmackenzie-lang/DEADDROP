import { FastifyInstance, FastifyPluginAsync } from 'fastify';
import { PythonBridge } from '../services/python-bridge.js';

const bridge = new PythonBridge();

export const evidenceRoutes: FastifyPluginAsync = async (app: FastifyInstance) => {
  // List evidence for a case
  app.get<{ Params: { caseId: string } }>('/:caseId', async (req, reply) => {
    const { caseId } = req.params;
    const result = await bridge.run(`case info ${caseId}`);
    return reply.send(result);
  });

  // Ingest disk image
  app.post('/disk', async (req, reply) => {
    const { case_id, image_path } = req.body as any;
    const result = await bridge.run(`ingest disk --image "${image_path}" --case ${case_id}`);
    return reply.code(201).send(result);
  });

  // Ingest memory dump
  app.post('/memory', async (req, reply) => {
    const { case_id, dump_path } = req.body as any;
    const result = await bridge.run(`ingest memory --dump "${dump_path}" --case ${case_id}`);
    return reply.code(201).send(result);
  });
};