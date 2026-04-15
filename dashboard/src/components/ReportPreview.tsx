import { useState } from 'react';

const API = '/api';

export default function ReportPreview({ caseId }: { caseId: string }) {
  const [generating, setGenerating] = useState(false);
  const [reportUrl, setReportUrl] = useState<string>('');
  const [format, setFormat] = useState<'html' | 'pdf'>('html');

  async function generateReport() {
    setGenerating(true);
    try {
      const res = await fetch(`${API}/reports/generate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ case_id: caseId, format }),
      });
      const data = await res.json();
      if (data.path) {
        setReportUrl(data.path);
      }
    } catch {
      // Generation failed
    }
    setGenerating(false);
  }

  return (
    <div className="space-y-6">
      <div className="bg-slate-900 rounded-xl border border-slate-800 p-6">
        <h2 className="text-lg font-bold text-white mb-4">📄 Report Generation</h2>
        <p className="text-slate-400 text-sm mb-4">
          Generate professional forensic case reports with evidence tagging, chain of custody, and timeline visualization.
        </p>
        <div className="flex gap-3 items-center">
          <select
            value={format}
            onChange={(e) => setFormat(e.target.value as any)}
            className="bg-slate-800 text-white border border-slate-700 rounded px-3 py-1.5 text-sm"
          >
            <option value="html">HTML</option>
            <option value="pdf">PDF</option>
          </select>
          <button
            onClick={generateReport}
            disabled={generating}
            className="bg-green-600 hover:bg-green-700 disabled:opacity-50 text-white px-4 py-2 rounded text-sm font-medium"
          >
            {generating ? 'Generating...' : 'Generate Report'}
          </button>
        </div>
      </div>

      {reportUrl && (
        <div className="bg-slate-900 rounded-xl border border-slate-800 p-6">
          <h3 className="text-sm font-semibold text-slate-300 mb-3">Report Ready</h3>
          <p className="text-slate-400 text-sm mb-2">Report saved to: <code className="text-blue-400">{reportUrl}</code></p>
          <a
            href={reportUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-block bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded text-sm font-medium"
          >
            Open Report
          </a>
        </div>
      )}
    </div>
  );
}