import { useState, useEffect } from 'react';

const API = '/api';

interface Artifact {
  id: string;
  source: string;
  category: string;
  severity: string;
  description: string;
  timestamp: string;
}

export default function ArtifactTable({ caseId }: { caseId: string }) {
  const [artifacts, setArtifacts] = useState<Artifact[]>([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState({ source: '', severity: '' });

  useEffect(() => {
    fetchArtifacts();
  }, [caseId]);

  async function fetchArtifacts() {
    setLoading(true);
    try {
      const res = await fetch(`${API}/artifacts/${caseId}`);
      const data = await res.json();
      setArtifacts(data.artifacts || []);
    } catch {
      setArtifacts([]);
    }
    setLoading(false);
  }

  const filtered = artifacts.filter((a) => {
    if (filter.source && a.source !== filter.source) return false;
    if (filter.severity && a.severity !== filter.severity) return false;
    return true;
  });

  const sources = [...new Set(artifacts.map((a) => a.source))];
  const severities = ['critical', 'high', 'medium', 'low', 'info'];

  if (loading) return <div className="text-slate-400 py-8">Loading artifacts...</div>;

  return (
    <div className="space-y-4">
      {/* Filters */}
      <div className="flex gap-3">
        <select
          value={filter.source}
          onChange={(e) => setFilter({ ...filter, source: e.target.value })}
          className="bg-slate-800 text-white border border-slate-700 rounded px-3 py-1.5 text-sm"
        >
          <option value="">All Sources</option>
          {sources.map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
        <select
          value={filter.severity}
          onChange={(e) => setFilter({ ...filter, severity: e.target.value })}
          className="bg-slate-800 text-white border border-slate-700 rounded px-3 py-1.5 text-sm"
        >
          <option value="">All Severities</option>
          {severities.map((s) => <option key={s} value={s}>{s.toUpperCase()}</option>)}
        </select>
        <span className="text-slate-400 text-sm self-center">{filtered.length} artifacts</span>
      </div>

      {/* Table */}
      <div className="bg-slate-900 rounded-xl border border-slate-800 overflow-hidden">
        <div className="overflow-auto max-h-[600px] scrollbar-thin">
          <table className="w-full text-sm">
            <thead className="sticky top-0 bg-slate-900">
              <tr className="text-slate-400 border-b border-slate-800">
                <th className="text-left py-3 px-4">Timestamp</th>
                <th className="text-left py-3 px-4">Source</th>
                <th className="text-left py-3 px-4">Category</th>
                <th className="text-left py-3 px-4">Severity</th>
                <th className="text-left py-3 px-4">Description</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((a, i) => (
                <tr key={i} className="border-b border-slate-800/50 hover:bg-slate-800/30">
                  <td className="py-2 px-4 font-mono text-xs text-slate-300">{a.timestamp?.slice(0, 19) || '—'}</td>
                  <td className="py-2 px-4 text-slate-300">{a.source}</td>
                  <td className="py-2 px-4 text-slate-400">{a.category}</td>
                  <td className="py-2 px-4">
                    <span className={`px-2 py-0.5 rounded text-xs font-semibold ${
                      a.severity === 'critical' ? 'bg-red-900 text-red-300' :
                      a.severity === 'high' ? 'bg-orange-900 text-orange-300' :
                      a.severity === 'medium' ? 'bg-amber-900 text-amber-300' :
                      a.severity === 'low' ? 'bg-green-900 text-green-300' :
                      'bg-slate-800 text-slate-400'
                    }`}>
                      {a.severity?.toUpperCase() || 'INFO'}
                    </span>
                  </td>
                  <td className="py-2 px-4 text-slate-300 max-w-lg truncate">{a.description}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}