const API = '/api';

export function useApi() {
  async function get(path: string): Promise<any> {
    const res = await fetch(`${API}${path}`);
    return res.json();
  }

  async function post(path: string, body: any): Promise<any> {
    const res = await fetch(`${API}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    return res.json();
  }

  return { get, post };
}