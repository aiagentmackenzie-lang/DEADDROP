import { useState, useEffect } from 'react';
import CaseOverview from './components/CaseOverview';
import TimelineView from './components/TimelineView';
import ArtifactTable from './components/ArtifactTable';
import HuntResults from './components/HuntResults';
import TriagePanel from './components/TriagePanel';
import ReportPreview from './components/ReportPreview';

type Tab = 'overview' | 'timeline' | 'artifacts' | 'hunt' | 'triage' | 'reports';

const API = '/api';

export default function App() {
  const [activeTab, setActiveTab] = useState<Tab>('overview');
  const [cases, setCases] = useState<any[]>([]);
  const [selectedCase, setSelectedCase] = useState<string>('');
  const [connected, setConnected] = useState(false);

  useEffect(() => {
    fetchCases();
    // WebSocket connection
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const ws = new WebSocket(`${protocol}//${window.location.host}/ws`);
    ws.onopen = () => setConnected(true);
    ws.onclose = () => setConnected(false);
    return () => ws.close();
  }, []);

  async function fetchCases() {
    try {
      const res = await fetch(`${API}/cases`);
      const data = await res.json();
      setCases(data.cases || []);
      if (data.cases?.length && !selectedCase) {
        setSelectedCase(data.cases[0].id);
      }
    } catch {
      // API not available
    }
  }

  async function createCase() {
    const name = prompt('Case name:');
    if (!name) return;
    await fetch(`${API}/cases`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, analyst: 'Analyst' }),
    });
    fetchCases();
  }

  const tabs: { id: Tab; label: string; icon: string }[] = [
    { id: 'overview', label: 'Overview', icon: '📋' },
    { id: 'timeline', label: 'Timeline', icon: '⏱️' },
    { id: 'artifacts', label: 'Artifacts', icon: '🔍' },
    { id: 'hunt', label: 'Hunt', icon: '🎯' },
    { id: 'triage', label: 'AI Triage', icon: '🤖' },
    { id: 'reports', label: 'Reports', icon: '📄' },
  ];

  return (
    <div className="min-h-screen bg-slate-950">
      {/* Header */}
      <header className="bg-slate-900 border-b border-slate-800 px-6 py-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <h1 className="text-xl font-bold text-white">
              <span className="text-blue-400">🔍 DEADDROP</span>
              <span className="text-slate-400 text-sm ml-2">Digital Forensics Toolkit</span>
            </h1>
            <span className={`text-xs px-2 py-1 rounded ${connected ? 'bg-green-900 text-green-400' : 'bg-red-900 text-red-400'}`}>
              {connected ? '● Connected' : '○ Disconnected'}
            </span>
          </div>
          <div className="flex items-center gap-3">
            <select
              value={selectedCase}
              onChange={(e) => setSelectedCase(e.target.value)}
              className="bg-slate-800 text-white border border-slate-700 rounded px-3 py-1.5 text-sm"
            >
              <option value="">Select case...</option>
              {cases.map((c: any) => (
                <option key={c.id} value={c.id}>{c.name} ({c.id})</option>
              ))}
            </select>
            <button
              onClick={createCase}
              className="bg-blue-600 hover:bg-blue-700 text-white px-3 py-1.5 rounded text-sm font-medium"
            >
              + New Case
            </button>
          </div>
        </div>
      </header>

      {/* Tab navigation */}
      <nav className="bg-slate-900/50 border-b border-slate-800 px-6">
        <div className="flex gap-1">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`px-4 py-3 text-sm font-medium border-b-2 transition-colors ${
                activeTab === tab.id
                  ? 'border-blue-400 text-blue-400'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              {tab.icon} {tab.label}
            </button>
          ))}
        </div>
      </nav>

      {/* Content */}
      <main className="p-6">
        {!selectedCase ? (
          <div className="text-center py-20 text-slate-400">
            <p className="text-lg">Select or create a case to begin analysis</p>
          </div>
        ) : (
          <>
            {activeTab === 'overview' && <CaseOverview caseId={selectedCase} />}
            {activeTab === 'timeline' && <TimelineView caseId={selectedCase} />}
            {activeTab === 'artifacts' && <ArtifactTable caseId={selectedCase} />}
            {activeTab === 'hunt' && <HuntResults caseId={selectedCase} />}
            {activeTab === 'triage' && <TriagePanel caseId={selectedCase} />}
            {activeTab === 'reports' && <ReportPreview caseId={selectedCase} />}
          </>
        )}
      </main>
    </div>
  );
}