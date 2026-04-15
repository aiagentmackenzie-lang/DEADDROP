import { useState, useEffect } from 'react';

const API = '/api';

export default function CaseOverview({ caseId }: { caseId: string }) {
  const [caseData, setCaseData] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchCase();
  }, [caseId]);

  async function fetchCase() {
    setLoading(true);
    try {
      const res = await fetch(`${API}/cases/${caseId}`);
      const data = await res.json();
      setCaseData(data);
    } catch {
      setCaseData(null);
    }
    setLoading(false);
  }

  if (loading) return <div className="text-slate-400 py-8">Loading case data...</div>;
  if (!caseData) return <div className="text-slate-400 py-8">Case not found</div>;

  return (
    <div className="space-y-6">
      {/* Case Info Card */}
      <div className="bg-slate-900 rounded-xl border border-slate-800 p-6">
        <h2 className="text-lg font-bold text-white mb-4">📋 Case Information</h2>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div>
            <span className="text-slate-400 text-sm">Case ID</span>
            <p className="text-white font-mono">{caseId}</p>
          </div>
          <div>
            <span className="text-slate-400 text-sm">Status</span>
            <p className={`font-semibold ${caseData.status === 'open' ? 'text-green-400' : 'text-yellow-400'}`}>
              {caseData.status?.toUpperCase() || 'OPEN'}
            </p>
          </div>
          <div>
            <span className="text-slate-400 text-sm">Analyst</span>
            <p className="text-white">{caseData.analyst || '—'}</p>
          </div>
          <div>
            <span className="text-slate-400 text-sm">Created</span>
            <p className="text-white">{caseData.created_at?.slice(0, 19) || '—'}</p>
          </div>
        </div>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard label="Evidence" value={caseData.evidence_count || 0} color="blue" />
        <StatCard label="Artifacts" value={caseData.artifact_count || 0} color="purple" />
        <StatCard label="Timeline" value={caseData.timeline_count || 0} color="cyan" />
        <StatCard label="Hunt Hits" value={caseData.hunt_count || 0} color="red" />
      </div>

      {/* Quick Actions */}
      <div className="bg-slate-900 rounded-xl border border-slate-800 p-6">
        <h2 className="text-lg font-bold text-white mb-4">⚡ Quick Actions</h2>
        <div className="flex gap-3 flex-wrap">
          <ActionButton label="Analyze Filesystem" onClick={() => runAction('analyze/filesystem')} />
          <ActionButton label="Run Triage" onClick={() => runAction('triage')} />
          <ActionButton label="YARA Scan" onClick={() => runAction('hunt/yara')} />
          <ActionButton label="Generate Report" onClick={() => runAction('reports/generate')} />
        </div>
      </div>
    </div>
  );

  async function runAction(action: string) {
    try {
      await fetch(`${API}/${action}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ case_id: caseId }),
      });
    } catch {
      // Action failed
    }
  }
}

function StatCard({ label, value, color }: { label: string; value: number; color: string }) {
  const colors: Record<string, string> = {
    blue: 'from-blue-600 to-blue-800',
    purple: 'from-purple-600 to-purple-800',
    cyan: 'from-cyan-600 to-cyan-800',
    red: 'from-red-600 to-red-800',
  };

  return (
    <div className={`bg-gradient-to-br ${colors[color]} rounded-xl p-5`}>
      <p className="text-3xl font-bold text-white">{value}</p>
      <p className="text-white/70 text-sm mt-1">{label}</p>
    </div>
  );
}

function ActionButton({ label, onClick }: { label: string; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      className="bg-slate-800 hover:bg-slate-700 text-white px-4 py-2 rounded-lg text-sm font-medium border border-slate-700 transition-colors"
    >
      {label}
    </button>
  );
}