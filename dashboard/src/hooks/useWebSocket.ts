import { useState, useEffect, useCallback } from 'react';

export function useWebSocket(url: string) {
  const [connected, setConnected] = useState(false);
  const [lastMessage, setLastMessage] = useState<any>(null);
  const wsRef = useState<WebSocket | null>(null);

  const connect = useCallback(() => {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const ws = new WebSocket(`${protocol}//${window.location.host}/ws`);

    ws.onopen = () => setConnected(true);
    ws.onclose = () => {
      setConnected(false);
      setTimeout(connect, 3000); // Reconnect
    };
    ws.onmessage = (event) => {
      try {
        setLastMessage(JSON.parse(event.data));
      } catch {
        setLastMessage(event.data);
      }
    };

    wsRef[1](ws);
  }, [url]);

  useEffect(() => {
    connect();
    return () => {
      wsRef[0]?.close();
    };
  }, [connect]);

  const send = useCallback((data: any) => {
    if (wsRef[0]?.readyState === WebSocket.OPEN) {
      wsRef[0].send(JSON.stringify(data));
    }
  }, []);

  return { connected, lastMessage, send };
}