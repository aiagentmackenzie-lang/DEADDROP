import { useState } from 'react';

const API = '/api';

export default function TriagePanel({ caseId }: { caseId: string }) {
  const [triageResult, setTriageResult] = useState<any>(null);
  const [summary, setSummary] = useState<string>('');
  const [running, setRunning] = useState(false);

  async function runTriage() {
    setRunning(true);
    try {
      const res = await fetch(`${API}/analyze/triage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ case_id: caseId }),
      });
      const data = await res.json();
      setTriageResult(data);
    } catch {
      setTriageResult({ error: 'Triage failed' });
    }
    setRunning(false);
  }

  async function getSummary() {
    setRunning(true);
    try {
      // Use triage summary endpoint
      const res = await fetch(`${API}/analyze/triage/summary`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ case_id: caseId }),
      });
      const data = await res.json();
      setSummary(data.summary || data.raw || JSON.stringify(data, null, 2));
    } catch {
      setSummary('Summary generation failed');
    }
    setRunning(false);
  }

  const riskColor = (level: string) => {
    switch (level) {
      case 'CRITICAL': return 'from-red-600 to-red-800';
      case 'HIGH': return 'from-orange-600 to-orange-800';
      case 'MEDIUM': return 'from-amber-600 to-amber-800';
      case 'LOW': return 'from-green-600 to-green-800';
      default: return 'from-slate-600 to-slate-800';
    }
  };

  return (
    <div className="space-y-6">
      {/* AI Triage Controls */}
      <div className="bg-slate-900 rounded-xl border border-slate-800 p-6">
        <h2 className="text-lg font-bold text-white mb-4">🤖 AI-Assisted Triage</h2>
        <p className="text-slate-400 text-sm mb-4">
          Automated anomaly detection and severity scoring powered by statistical analysis and LLM.
        </p>
        <div className="flex gap-3">
          <button
            onClick={runTriage}
            disabled={running}
            className="bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white px-4 py-2 rounded text-sm font-medium"
          >
            {running ? 'Analyzing...' : '🔍 Run Triage'}
          </button>
          <button
            onClick={getSummary}
            disabled={running}
            className="bg-purple-600 hover:bg-purple-700 disabled:opacity-50 text-white px-4 py-2 rounded text-sm font-medium"
          >
            {running ? 'Generating...' : '📝 Generate Summary'}
          </button>
        </div>
      </div>

      {/* Risk Score */}
      {triageResult && (
        <div className={`bg-gradient-to-r ${riskColor(triageResult.risk_level || 'MINIMAL')} rounded-xl p-6`}>
          <div className="flex items-center justify-between">
            <div>
              <p className="text-white/70 text-sm">Risk Score</p>
              <p className="text-4xl font-bold text-white">{triageResult.risk_score ?? 0}</p>
            </div>
            <div className="text-right">
              <p className="text-white/70 text-sm">Risk Level</p>
              <p className="text-2xl font-bold text-white">{triageResult.risk_level || 'MINIMAL'}</p>
            </div>
          </div>
          <div className="grid grid-cols-3 gap-4 mt-4">
            <div className="bg-white/10 rounded-lg p-3">
              <p className="text-white text-xl font-bold">{triageResult.anomalies ?? 0}</p>
              <p className="text-white/60 text-xs">Anomalies</p>
            </div>
            <div className="bg-white/10 rounded-lg p-3">
              <p className="text-white text-xl font-bold">{triageResult.high ?? 0}</p>
              <p className="text-white/60 text-xs">High/Critical</p>
            </div>
            <div className="bg-white/10 rounded-lg p-3">
              <p className="text-white text-xl font-bold">{triageResult.critical ?? 0}</p>
              <p className="text-white/60 text-xs">Critical</p>
            </div>
          </div>
        </div>
      )}

      {/* Summary */}
      {summary && (
        <div className="bg-slate-900 rounded-xl border border-slate-800 p-6">
          <h3 className="text-sm font-semibold text-slate-300 mb-3">📝 Case Summary</h3>
          <pre className="text-sm text-slate-300 whitespace-pre-wrap">{summary}</pre>
        </div>
      )}
    </div>
  );
}