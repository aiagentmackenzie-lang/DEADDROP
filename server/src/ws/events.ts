import { FastifyInstance } from 'fastify';

export function registerWS(app: FastifyInstance) {
  app.get('/ws', { websocket: true }, (socket, req) => {
    socket.on('message', (msg: Buffer) => {
      try {
        const data = JSON.parse(msg.toString());
        // Echo back with status (simple real-time bridge)
        socket.send(JSON.stringify({
          type: 'ack',
          action: data.action,
          timestamp: new Date().toISOString(),
        }));
      } catch {
        socket.send(JSON.stringify({ type: 'error', message: 'Invalid JSON' }));
      }
    });

    socket.on('close', () => {
      // Client disconnected
    });
  });
}