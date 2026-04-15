import { useState } from 'react';

const API = '/api';

export default function HuntResults({ caseId }: { caseId: string }) {
  const [running, setRunning] = useState(false);
  const [results, setResults] = useState<any>(null);

  async function runHunt(type: 'yara' | 'ioc' | 'pack', value: string) {
    setRunning(true);
    try {
      const body: any = { case_id: caseId };
      if (type === 'yara') body.yara_rules = value;
      else if (type === 'ioc') body.ioc_path = value;
      else body.pack = value;

      const res = await fetch(`${API}/hunt/${type === 'pack' ? 'yara' : type}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      const data = await res.json();
      setResults(data);
    } catch {
      setResults({ error: 'Hunt failed' });
    }
    setRunning(false);
  }

  return (
    <div className="space-y-6">
      {/* Hunt Controls */}
      <div className="bg-slate-900 rounded-xl border border-slate-800 p-6">
        <h2 className="text-lg font-bold text-white mb-4">🎯 Artifact Hunt</h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="space-y-2">
            <h3 className="text-sm font-semibold text-slate-300">YARA Scan</h3>
            <p className="text-xs text-slate-500">Scan evidence with YARA rules</p>
            <button
              onClick={() => runHunt('yara', '')}
              disabled={running}
              className="bg-orange-600 hover:bg-orange-700 disabled:opacity-50 text-white px-4 py-2 rounded text-sm font-medium w-full"
            >
              {running ? 'Running...' : 'Run YARA Scan'}
            </button>
          </div>
          <div className="space-y-2">
            <h3 className="text-sm font-semibold text-slate-300">IOC Match</h3>
            <p className="text-xs text-slate-500">Match indicators of compromise</p>
            <button
              onClick={() => runHunt('ioc', '')}
              disabled={running}
              className="bg-purple-600 hover:bg-purple-700 disabled:opacity-50 text-white px-4 py-2 rounded text-sm font-medium w-full"
            >
              {running ? 'Running...' : 'Run IOC Match'}
            </button>
          </div>
          <div className="space-y-2">
            <h3 className="text-sm font-semibold text-slate-300">Hunt Packs</h3>
            <p className="text-xs text-slate-500">Pre-built detection packs</p>
            <div className="space-y-1">
              {['persistence', 'lateral_movement', 'exfiltration'].map((pack) => (
                <button
                  key={pack}
                  onClick={() => runHunt('pack', pack)}
                  disabled={running}
                  className="bg-slate-800 hover:bg-slate-700 disabled:opacity-50 text-white px-3 py-1.5 rounded text-xs font-medium w-full"
                >
                  {pack.replace('_', ' ')}
                </button>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Results */}
      {results && (
        <div className="bg-slate-900 rounded-xl border border-slate-800 p-6">
          <h3 className="text-sm font-semibold text-slate-300 mb-3">Hunt Results</h3>
          <pre className="text-xs text-slate-300 overflow-auto max-h-96 scrollbar-thin bg-slate-950 p-4 rounded">
            {JSON.stringify(results, null, 2)}
          </pre>
        </div>
      )}
    </div>
  );
}