import { useState, useEffect, useRef } from 'react';
import * as d3 from 'd3';

const API = '/api';

interface TimelineEntry {
  timestamp: string;
  source: string;
  severity: string;
  description: string;
}

export default function TimelineView({ caseId }: { caseId: string }) {
  const [entries, setEntries] = useState<TimelineEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const svgRef = useRef<SVGSVGElement>(null);

  useEffect(() => {
    fetchTimeline();
  }, [caseId]);

  useEffect(() => {
    if (entries.length > 0 && svgRef.current) {
      renderD3Timeline();
    }
  }, [entries]);

  async function fetchTimeline() {
    setLoading(true);
    try {
      const res = await fetch(`${API}/cases/${caseId}/timeline`);
      const data = await res.json();
      setEntries(data.timeline || []);
    } catch {
      setEntries([]);
    }
    setLoading(false);
  }

  function renderD3Timeline() {
    if (!svgRef.current) return;

    const svg = d3.select(svgRef.current);
    svg.selectAll('*').remove();

    const margin = { top: 20, right: 30, bottom: 40, left: 60 };
    const width = svgRef.current.clientWidth - margin.left - margin.right;
    const height = 400 - margin.top - margin.bottom;

    const g = svg
      .attr('width', width + margin.left + margin.right)
      .attr('height', height + margin.top + margin.bottom)
      .append('g')
      .attr('transform', `translate(${margin.left},${margin.top})`);

    const parseDate = d3.isoParse;
    const validEntries = entries.filter((e) => e.timestamp && parseDate(e.timestamp));

    if (validEntries.length === 0) return;

    const x = d3.scaleTime()
      .domain(d3.extent(validEntries, (d) => parseDate(d.timestamp)!) as [Date, Date])
      .range([0, width]);

    const sources = [...new Set(validEntries.map((e) => e.source))];
    const y = d3.scaleBand()
      .domain(sources)
      .range([0, height])
      .padding(0.3);

    const severityColor = (sev: string) => {
      switch (sev) {
        case 'critical': return '#dc2626';
        case 'high': return '#ea580c';
        case 'medium': return '#d97706';
        case 'low': return '#22c55e';
        default: return '#64748b';
      }
    };

    // Axes
    g.append('g')
      .attr('transform', `translate(0,${height})`)
      .call(d3.axisBottom(x).ticks(10))
      .selectAll('text')
      .attr('fill', '#94a3b8')
      .style('font-size', '10px');

    g.append('g')
      .call(d3.axisLeft(y))
      .selectAll('text')
      .attr('fill', '#94a3b8')
      .style('font-size', '11px');

    // Grid lines
    g.append('g')
      .attr('class', 'grid')
      .call(d3.axisLeft(y).tickSize(-width).tickFormat('' as any))
      .selectAll('line')
      .attr('stroke', '#1e293b');

    // Data points
    g.selectAll('circle')
      .data(validEntries)
      .join('circle')
      .attr('cx', (d) => x(parseDate(d.timestamp)!))
      .attr('cy', (d) => y(d.source)! + y.bandwidth() / 2)
      .attr('r', (d) => d.severity === 'critical' ? 6 : d.severity === 'high' ? 5 : 3)
      .attr('fill', (d) => severityColor(d.severity))
      .attr('opacity', 0.8)
      .on('mouseover', function (event, d) {
        d3.select(this).attr('r', 8).attr('opacity', 1);
      })
      .on('mouseout', function (event, d) {
        d3.select(this)
          .attr('r', d.severity === 'critical' ? 6 : d.severity === 'high' ? 5 : 3)
          .attr('opacity', 0.8);
      });

    // Axis styling
    g.selectAll('.domain, .tick line').attr('stroke', '#334155');
  }

  if (loading) return <div className="text-slate-400 py-8">Loading timeline...</div>;

  return (
    <div className="space-y-6">
      <div className="bg-slate-900 rounded-xl border border-slate-800 p-6">
        <div className="flex justify-between items-center mb-4">
          <h2 className="text-lg font-bold text-white">⏱️ Timeline</h2>
          <span className="text-slate-400 text-sm">{entries.length} entries</span>
        </div>

        {/* D3 Interactive Timeline */}
        <svg ref={svgRef} className="w-full" style={{ minHeight: '400px' }} />

        {/* Legend */}
        <div className="flex gap-4 mt-4 text-xs">
          {['critical', 'high', 'medium', 'low', 'info'].map((sev) => (
            <span key={sev} className="flex items-center gap-1">
              <span className={`w-3 h-3 rounded-full ${
                sev === 'critical' ? 'bg-red-600' :
                sev === 'high' ? 'bg-orange-600' :
                sev === 'medium' ? 'bg-amber-600' :
                sev === 'low' ? 'bg-green-600' : 'bg-slate-500'
              }`} />
              {sev.charAt(0).toUpperCase() + sev.slice(1)}
            </span>
          ))}
        </div>
      </div>

      {/* Table view */}
      <div className="bg-slate-900 rounded-xl border border-slate-800 p-6">
        <h3 className="text-sm font-semibold text-slate-300 mb-3">Recent Events</h3>
        <div className="overflow-auto max-h-96 scrollbar-thin">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-slate-400 border-b border-slate-800">
                <th className="text-left py-2 px-3">Timestamp</th>
                <th className="text-left py-2 px-3">Source</th>
                <th className="text-left py-2 px-3">Severity</th>
                <th className="text-left py-2 px-3">Description</th>
              </tr>
            </thead>
            <tbody>
              {entries.slice(0, 100).map((entry, i) => (
                <tr key={i} className="border-b border-slate-800/50 hover:bg-slate-800/30">
                  <td className="py-2 px-3 font-mono text-xs text-slate-300">{entry.timestamp?.slice(0, 19)}</td>
                  <td className="py-2 px-3 text-slate-300">{entry.source}</td>
                  <td className="py-2 px-3">
                    <span className={`px-2 py-0.5 rounded text-xs font-semibold ${
                      entry.severity === 'critical' ? 'bg-red-900 text-red-300' :
                      entry.severity === 'high' ? 'bg-orange-900 text-orange-300' :
                      entry.severity === 'medium' ? 'bg-amber-900 text-amber-300' :
                      entry.severity === 'low' ? 'bg-green-900 text-green-300' :
                      'bg-slate-800 text-slate-400'
                    }`}>
                      {entry.severity?.toUpperCase() || 'INFO'}
                    </span>
                  </td>
                  <td className="py-2 px-3 text-slate-300 max-w-md truncate">{entry.description}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}