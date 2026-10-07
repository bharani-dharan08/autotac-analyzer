/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect, useRef } from 'react';
import {
  Activity,
  Upload,
  Download,
  AlertTriangle,
  CheckCircle,
  Server,
  ShieldAlert,
  Globe,
  RefreshCw,
  Sliders,
  Database,
  Search,
  Filter,
  ArrowRight,
  Terminal,
  Cpu,
  BookOpen,
  Key,
  Cloud,
  GitMerge,
  ChevronDown,
  ChevronRight,
  FileText,
  Copy,
  Check,
  Sparkles,
  Code,
  FileCode,
  Shield,
  PhoneCall,
  PhoneOff,
  Volume2,
  VolumeX,
  Radio
} from 'lucide-react';
import { NetworkPacket, NetworkFlow, PcapAnalysisResult } from './utils/pcapParser';
import * as d3 from 'd3';

interface PacketTimelineChartProps {
  packets: NetworkPacket[];
}

function PacketTimelineChart({ packets }: PacketTimelineChartProps) {
  const svgRef = useRef<SVGSVGElement | null>(null);

  useEffect(() => {
    if (!svgRef.current || !packets || packets.length === 0) return;

    // Filter to TCP/IP packets
    const tcpPacketsList = packets.filter(
      p => p.protocol === 'TCP' || p.protocol === 'HTTP' || p.protocol === 'FTP'
    );

    if (tcpPacketsList.length === 0) {
      d3.select(svgRef.current).selectAll('*').remove();
      return;
    }

    const timestamps = tcpPacketsList.map(p => p.timestamp);
    const minTime = Math.min(...timestamps);
    const maxTime = Math.max(...timestamps);
    const duration = Math.max(1, maxTime - minTime);

    const binCount = 15;
    const binSize = duration / binCount;

    const data = Array.from({ length: binCount }).map((_, idx) => {
      const start = minTime + idx * binSize;
      const end = start + binSize;
      const binPkts = tcpPacketsList.filter(p => p.timestamp >= start && p.timestamp < end);
      const total = binPkts.length;
      const retrans = binPkts.filter(p => p.isRetransmission).length;

      return {
        binIndex: idx,
        timeLabel: `${((idx * binSize) / 1000).toFixed(1)}s`,
        total,
        retrans,
      };
    });

    // Chart Dimensions
    const margin = { top: 20, right: 30, bottom: 30, left: 40 };
    const width = 600;
    const height = 180;

    const svg = d3.select(svgRef.current);
    svg.selectAll('*').remove();

    svg.attr('viewBox', `0 0 ${width} ${height}`);

    // Scales
    const xScale = d3.scaleLinear()
      .domain([0, binCount - 1])
      .range([margin.left, width - margin.right]);

    const maxVal = d3.max(data, d => Math.max(d.total, d.retrans * 1.5)) || 10;
    const yScale = d3.scaleLinear()
      .domain([0, maxVal])
      .range([height - margin.bottom, margin.top]);

    // X Axis
    const xAxis = d3.axisBottom(xScale)
      .ticks(binCount)
      .tickFormat((d) => {
        const item = data[d as number];
        return item ? item.timeLabel : '';
      });

    svg.append('g')
      .attr('transform', `translate(0, ${height - margin.bottom})`)
      .call(xAxis)
      .attr('color', '#1e293b')
      .selectAll('text')
      .style('fill', '#64748b')
      .style('font-family', 'var(--font-mono, monospace)')
      .style('font-size', '8px');

    // Y Axis
    const yAxis = d3.axisLeft(yScale)
      .ticks(4)
      .tickFormat(d3.format('d'));

    svg.append('g')
      .attr('transform', `translate(${margin.left}, 0)`)
      .call(yAxis)
      .attr('color', '#1e293b')
      .selectAll('text')
      .style('fill', '#64748b')
      .style('font-family', 'var(--font-mono, monospace)')
      .style('font-size', '8px');

    // Grid lines
    svg.append('g')
      .attr('transform', `translate(${margin.left}, 0)`)
      .call(d3.axisLeft(yScale).ticks(4).tickSize(-width + margin.left + margin.right).tickFormat(() => ''))
      .attr('color', '#0f172a')
      .attr('stroke-opacity', 0.2);

    // Gradients
    const defs = svg.append('defs');
    
    // Blue Area Gradient
    const blueGradient = defs.append('linearGradient')
      .attr('id', 'blue-gradient')
      .attr('x1', '0%')
      .attr('y1', '0%')
      .attr('x2', '0%')
      .attr('y2', '100%');

    blueGradient.append('stop')
      .attr('offset', '0%')
      .attr('stop-color', '#06b6d4')
      .attr('stop-opacity', 0.15);

    blueGradient.append('stop')
      .attr('offset', '100%')
      .attr('stop-color', '#06b6d4')
      .attr('stop-opacity', 0);

    // Area path for volume background
    const areaGen = d3.area<typeof data[0]>()
      .x(d => xScale(d.binIndex))
      .y0(height - margin.bottom)
      .y1(d => yScale(d.total))
      .curve(d3.curveMonotoneX);

    svg.append('path')
      .datum(data)
      .attr('fill', 'url(#blue-gradient)')
      .attr('d', areaGen);

    // Line paths
    const totalLine = d3.line<typeof data[0]>()
      .x(d => xScale(d.binIndex))
      .y(d => yScale(d.total))
      .curve(d3.curveMonotoneX);

    const retransLine = d3.line<typeof data[0]>()
      .x(d => xScale(d.binIndex))
      .y(d => yScale(d.retrans))
      .curve(d3.curveMonotoneX);

    // Draw lines
    svg.append('path')
      .datum(data)
      .attr('fill', 'none')
      .attr('stroke', '#06b6d4') // Cyan-500
      .attr('stroke-width', 2)
      .attr('d', totalLine);

    svg.append('path')
      .datum(data)
      .attr('fill', 'none')
      .attr('stroke', '#ef4444') // Red-500
      .attr('stroke-width', 1.5)
      .attr('stroke-dasharray', '3,3')
      .attr('d', retransLine);

    // Highlight Retransmissions
    const spikes = data.filter(d => d.retrans > 0);

    // Red ping glow animation
    svg.selectAll('.spike-pulse')
      .data(spikes)
      .enter()
      .append('circle')
      .attr('cx', d => xScale(d.binIndex))
      .attr('cy', d => yScale(d.retrans))
      .attr('r', 6)
      .attr('fill', '#ef4444')
      .attr('opacity', 0.3)
      .attr('class', 'animate-ping');

    // Inner Red Dot
    svg.selectAll('.spike-dot')
      .data(spikes)
      .enter()
      .append('circle')
      .attr('cx', d => xScale(d.binIndex))
      .attr('cy', d => yScale(d.retrans))
      .attr('r', 3.5)
      .attr('fill', '#ef4444')
      .attr('stroke', '#ffffff')
      .attr('stroke-width', 1);

  }, [packets]);

  return (
    <div className="flex flex-col gap-2">
      <div className="flex items-center justify-between text-[11px] text-slate-400 font-medium">
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5">
            <span className="w-2 h-2 bg-cyan-500 rounded-full inline-block"></span>
            <span>Flow Load (TCP pkts)</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-2 h-2 bg-red-500 rounded-full inline-block animate-pulse"></span>
            <span className="text-red-400">Packet Loss Spikes</span>
          </div>
        </div>
        <span className="text-[10px] font-mono text-slate-500">Interval-binned timeline</span>
      </div>
      <div className="bg-slate-950 border border-slate-900 rounded-lg p-2 overflow-hidden">
        <svg ref={svgRef} className="w-full h-auto max-h-[220px]"></svg>
      </div>
    </div>
  );
}

interface TcpRttLatencyChartProps {
  packets: NetworkPacket[];
}

function TcpRttLatencyChart({ packets }: TcpRttLatencyChartProps) {
  const svgRef = useRef<SVGSVGElement | null>(null);

  useEffect(() => {
    if (!svgRef.current || !packets || packets.length === 0) return;

    // Filter packets that have valid RTT values calculated
    const rttPackets = packets.filter(p => p.rtt !== undefined);

    if (rttPackets.length === 0) {
      // Show empty state inside the SVG
      const svg = d3.select(svgRef.current);
      svg.selectAll('*').remove();
      svg.attr('viewBox', '0 0 600 180');
      svg.append('text')
        .attr('x', 300)
        .attr('y', 90)
        .attr('text-anchor', 'middle')
        .attr('fill', '#64748b')
        .style('font-family', 'sans-serif')
        .style('font-size', '12px')
        .text('No active RTT latency values recorded for this stream.');
      return;
    }

    // Chart Dimensions
    const margin = { top: 20, right: 30, bottom: 30, left: 40 };
    const width = 600;
    const height = 180;

    const svg = d3.select(svgRef.current);
    svg.selectAll('*').remove();
    svg.attr('viewBox', `0 0 ${width} ${height}`);

    const timestamps = rttPackets.map(p => p.timestamp);
    const minTime = Math.min(...timestamps);
    const maxTime = Math.max(...timestamps);

    // Scales
    const xScale = d3.scaleLinear()
      .domain([minTime, maxTime])
      .range([margin.left, width - margin.right]);

    const maxRttVal = d3.max(rttPackets, p => p.rtt!) || 10;
    const yScale = d3.scaleLinear()
      .domain([0, maxRttVal * 1.15]) // pad slightly
      .range([height - margin.bottom, margin.top]);

    // X Axis (Time offset in seconds)
    const xAxis = d3.axisBottom(xScale)
      .ticks(10)
      .tickFormat((d) => `${((d as number - minTime) / 1000).toFixed(1)}s`);

    svg.append('g')
      .attr('transform', `translate(0, ${height - margin.bottom})`)
      .call(xAxis)
      .attr('color', '#1e293b')
      .selectAll('text')
      .style('fill', '#64748b')
      .style('font-family', 'var(--font-mono, monospace)')
      .style('font-size', '8px');

    // Y Axis (RTT in ms)
    const yAxis = d3.axisLeft(yScale)
      .ticks(4)
      .tickFormat((d) => `${d}ms`);

    svg.append('g')
      .attr('transform', `translate(${margin.left}, 0)`)
      .call(yAxis)
      .attr('color', '#1e293b')
      .selectAll('text')
      .style('fill', '#64748b')
      .style('font-family', 'var(--font-mono, monospace)')
      .style('font-size', '8px');

    // Grid lines
    svg.append('g')
      .attr('transform', `translate(${margin.left}, 0)`)
      .call(d3.axisLeft(yScale).ticks(4).tickSize(-width + margin.left + margin.right).tickFormat(() => ''))
      .attr('color', '#0f172a')
      .attr('stroke-opacity', 0.2);

    // Latency curve path
    const rttLine = d3.line<NetworkPacket>()
      .x(p => xScale(p.timestamp))
      .y(p => yScale(p.rtt!))
      .curve(d3.curveMonotoneX);

    // Add path with gradient glow
    const defs = svg.append('defs');
    const pathGradient = defs.append('linearGradient')
      .attr('id', 'rtt-gradient')
      .attr('x1', '0%')
      .attr('y1', '0%')
      .attr('x2', '0%')
      .attr('y2', '100%');

    pathGradient.append('stop')
      .attr('offset', '0%')
      .attr('stop-color', '#fb923c') // amber-400
      .attr('stop-opacity', 0.2);

    pathGradient.append('stop')
      .attr('offset', '100%')
      .attr('stop-color', '#fb923c')
      .attr('stop-opacity', 0);

    const rttArea = d3.area<NetworkPacket>()
      .x(p => xScale(p.timestamp))
      .y0(height - margin.bottom)
      .y1(p => yScale(p.rtt!))
      .curve(d3.curveMonotoneX);

    // Draw area fill
    svg.append('path')
      .datum(rttPackets)
      .attr('fill', 'url(#rtt-gradient)')
      .attr('d', rttArea);

    // Draw main latency line
    svg.append('path')
      .datum(rttPackets)
      .attr('fill', 'none')
      .attr('stroke', '#f97316') // orange-500
      .attr('stroke-width', 2)
      .attr('d', rttLine);

    // Draw points for each packet with RTT calculated
    svg.selectAll('.rtt-dot')
      .data(rttPackets)
      .enter()
      .append('circle')
      .attr('cx', p => xScale(p.timestamp))
      .attr('cy', p => yScale(p.rtt!))
      .attr('r', 3.5)
      .attr('fill', p => p.rtt! > 150 ? '#ef4444' : '#fb923c') // red dot for high latency spikes
      .attr('stroke', '#0f172a')
      .attr('stroke-width', 0.5)
      .attr('class', 'cursor-pointer hover:r-[5] transition-all')
      .append('title')
      .text(p => `Packet #${p.index + 1}\nTime: ${((p.timestamp - minTime)/1000).toFixed(2)}s\nRTT: ${p.rtt!.toFixed(1)}ms\nFlow: ${p.srcIp} -> ${p.dstIp}`);

  }, [packets]);

  return (
    <div className="flex flex-col gap-2">
      <div className="flex items-center justify-between text-[11px] text-slate-400 font-medium">
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5">
            <span className="w-2 h-2 bg-orange-500 rounded-full inline-block"></span>
            <span>RTT Latency (ms)</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-2 h-2 bg-red-500 rounded-full inline-block animate-pulse"></span>
            <span className="text-red-400">Latency Spikes (&gt;150ms)</span>
          </div>
        </div>
        <span className="text-[10px] font-mono text-slate-500">Real-time Stream RTT Tracker</span>
      </div>
      <div className="bg-slate-950 border border-slate-900 rounded-lg p-2 overflow-hidden">
        <svg ref={svgRef} className="w-full h-auto max-h-[220px]"></svg>
      </div>
    </div>
  );
}

interface NetworkTopologyGraphProps {
  analysisResult: PcapAnalysisResult;
}

function NetworkTopologyGraph({ analysisResult }: NetworkTopologyGraphProps) {
  const svgRef = useRef<SVGSVGElement | null>(null);
  const [minPacketVolume, setMinPacketVolume] = useState<number>(1);
  const [selectedNode, setSelectedNode] = useState<any | null>(null);
  const [selectedEdge, setSelectedEdge] = useState<any | null>(null);

  useEffect(() => {
    if (!svgRef.current || !analysisResult) return;

    const svg = d3.select(svgRef.current);
    svg.selectAll('*').remove();

    const rawConnections = analysisResult.connections || [];
    
    // IP -> Node Details Mapping
    const ipMap: Record<string, { id: string; packetsSent: number; packetsRecv: number; totalBytes: number; isServer: boolean; isAttackerOrRisk: boolean; totalLoss: number }> = {};

    rawConnections.forEach(c => {
      // Source IP details
      if (!ipMap[c.srcIp]) {
        ipMap[c.srcIp] = {
          id: c.srcIp,
          packetsSent: 0,
          packetsRecv: 0,
          totalBytes: 0,
          isServer: c.srcIp.endsWith('.10') || c.srcIp.endsWith('.100') || c.srcIp.endsWith('.1'),
          isAttackerOrRisk: c.srcIp === '172.16.5.42',
          totalLoss: 0
        };
      }
      ipMap[c.srcIp].packetsSent += c.totalPackets;
      ipMap[c.srcIp].totalBytes += c.totalBytes;
      ipMap[c.srcIp].totalLoss += c.retransmissions;

      // Destination IP details
      if (!ipMap[c.dstIp]) {
        ipMap[c.dstIp] = {
          id: c.dstIp,
          packetsSent: 0,
          packetsRecv: 0,
          totalBytes: 0,
          isServer: c.dstIp.endsWith('.10') || c.dstIp.endsWith('.100') || c.dstIp.endsWith('.1') || c.dstIp === '8.8.8.8',
          isAttackerOrRisk: false,
          totalLoss: 0
        };
      }
      ipMap[c.dstIp].packetsRecv += c.totalPackets;
      ipMap[c.dstIp].totalBytes += c.totalBytes;
    });

    const nodes = Object.values(ipMap);

    // Extract links (edges) based on min volume filter
    const links = rawConnections
      .filter(c => c.totalPackets >= minPacketVolume)
      .map(c => ({
        id: `${c.srcIp}-${c.dstIp}`,
        source: c.srcIp,
        target: c.dstIp,
        value: c.totalBytes,
        packets: c.totalPackets,
        retransmissions: c.retransmissions,
        retransmissionRate: c.retransmissionRate
      }));

    if (nodes.length === 0) {
      svg.attr('viewBox', '0 0 800 450')
        .append('text')
        .attr('x', 400)
        .attr('y', 225)
        .attr('text-anchor', 'middle')
        .attr('fill', '#64748b')
        .style('font-family', 'sans-serif')
        .text('No interconnected network nodes identified.');
      return;
    }

    const width = 800;
    const height = 450;
    svg.attr('viewBox', `0 0 ${width} ${height}`);

    // Container for zooming/panning
    const container = svg.append('g');

    const zoom = d3.zoom<SVGSVGElement, unknown>()
      .scaleExtent([0.3, 4])
      .on('zoom', (event) => {
        container.attr('transform', event.transform);
      });

    svg.call(zoom);

    // Setup Forces
    const simulation = d3.forceSimulation<any>(nodes)
      .force('link', d3.forceLink<any, any>(links).id(d => d.id).distance(150))
      .force('charge', d3.forceManyBody().strength(-220))
      .force('center', d3.forceCenter(width / 2, height / 2))
      .force('collision', d3.forceCollide().radius(35));

    const defs = svg.append('defs');

    // Arrow markers
    defs.append('marker')
      .attr('id', 'arrow-topo')
      .attr('viewBox', '0 -5 10 10')
      .attr('refX', 22)
      .attr('refY', 0)
      .attr('markerWidth', 5)
      .attr('markerHeight', 5)
      .attr('orient', 'auto')
      .append('path')
      .attr('fill', '#475569')
      .attr('d', 'M0,-5L10,0L0,5');

    defs.append('marker')
      .attr('id', 'arrow-topo-loss')
      .attr('viewBox', '0 -5 10 10')
      .attr('refX', 22)
      .attr('refY', 0)
      .attr('markerWidth', 5)
      .attr('markerHeight', 5)
      .attr('orient', 'auto')
      .append('path')
      .attr('fill', '#f87171')
      .attr('d', 'M0,-5L10,0L0,5');

    // Draw links
    const link = container.append('g')
      .selectAll('line')
      .data(links)
      .join('line')
      .attr('stroke', d => d.retransmissions > 0 ? '#ef4444' : '#334155')
      .attr('stroke-opacity', 0.6)
      .attr('stroke-width', d => Math.max(1.5, Math.min(5, Math.log10(d.value) * 1.1)))
      .attr('marker-end', d => d.retransmissions > 0 ? 'url(#arrow-topo-loss)' : 'url(#arrow-topo)')
      .attr('class', 'transition-all cursor-pointer')
      .on('click', (event, d) => {
        event.stopPropagation();
        setSelectedEdge(d);
        setSelectedNode(null);
      });

    // Draw nodes
    const node = container.append('g')
      .selectAll('.node-group')
      .data(nodes)
      .join('g')
      .attr('class', 'node-group cursor-pointer')
      .call(d3.drag<any, any>()
        .on('start', dragstarted)
        .on('drag', dragged)
        .on('end', dragended))
      .on('click', (event, d) => {
        event.stopPropagation();
        setSelectedNode(ipMap[d.id]);
        setSelectedEdge(null);
      });

    // Node Base Circle
    node.append('circle')
      .attr('r', d => {
        const packets = d.packetsSent + d.packetsRecv;
        return Math.max(14, Math.min(26, 12 + Math.log10(packets + 1) * 3));
      })
      .attr('fill', d => {
        if (d.isAttackerOrRisk) return '#f43f5e';
        if (d.totalLoss > 5) return '#f97316';
        if (d.isServer) return '#10b981';
        return '#06b6d4';
      })
      .attr('stroke', d => {
        if (selectedNode && selectedNode.id === d.id) return '#ffffff';
        return '#0f172a';
      })
      .attr('stroke-width', d => (selectedNode && selectedNode.id === d.id) ? 2.5 : 1.5);

    // Node pulsing overlay ring
    node.filter((d: any) => d.isAttackerOrRisk || d.totalLoss > 5)
      .append('circle')
      .attr('r', d => {
        const packets = d.packetsSent + d.packetsRecv;
        return Math.max(14, Math.min(26, 12 + Math.log10(packets + 1) * 3)) + 4;
      })
      .attr('fill', 'none')
      .attr('stroke', d => d.isAttackerOrRisk ? '#f43f5e' : '#f97316')
      .attr('stroke-width', 1)
      .attr('stroke-opacity', 0.5)
      .attr('class', 'animate-pulse');

    // Label
    node.append('text')
      .attr('dy', -18)
      .attr('text-anchor', 'middle')
      .text(d => d.id)
      .style('fill', '#cbd5e1')
      .style('font-family', 'var(--font-mono, monospace)')
      .style('font-size', '8px')
      .style('font-weight', '600')
      .style('pointer-events', 'none')
      .style('text-shadow', '0 1px 2px rgba(0,0,0,0.8)');

    // Text markers inside nodes
    node.filter((d: any) => d.isServer)
      .append('text')
      .attr('dy', '0.35em')
      .attr('text-anchor', 'middle')
      .text('SRV')
      .style('fill', '#ffffff')
      .style('font-family', 'var(--font-mono, monospace)')
      .style('font-size', '7px')
      .style('font-weight', 'bold')
      .style('pointer-events', 'none');

    node.filter((d: any) => d.isAttackerOrRisk)
      .append('text')
      .attr('dy', '0.35em')
      .attr('text-anchor', 'middle')
      .text('!')
      .style('fill', '#ffffff')
      .style('font-family', 'sans-serif')
      .style('font-size', '9px')
      .style('font-weight', 'bold')
      .style('pointer-events', 'none');

    // Simulation simulation ticks
    simulation.on('tick', () => {
      link
        .attr('x1', (d: any) => d.source.x)
        .attr('y1', (d: any) => d.source.y)
        .attr('x2', (d: any) => d.target.x)
        .attr('y2', (d: any) => d.target.y);

      node
        .attr('transform', (d: any) => `translate(${d.x}, ${d.y})`);
    });

    function dragstarted(event: any, d: any) {
      if (!event.active) simulation.alphaTarget(0.3).restart();
      d.fx = d.x;
      d.fy = d.y;
    }

    function dragged(event: any, d: any) {
      d.fx = event.x;
      d.fy = event.y;
    }

    function dragended(event: any, d: any) {
      if (!event.active) simulation.alphaTarget(0);
      d.fx = null;
      d.fy = null;
    }

    svg.on('click', () => {
      setSelectedNode(null);
      setSelectedEdge(null);
    });

  }, [analysisResult, minPacketVolume, selectedNode?.id]);

  return (
    <div className="grid grid-cols-1 xl:grid-cols-4 gap-6">
      {/* Topology Canvas */}
      <div className="xl:col-span-3 bg-slate-950 border border-slate-900 rounded-xl p-4 flex flex-col gap-4 relative">
        <div className="flex items-center justify-between border-b border-slate-900 pb-3">
          <div className="flex flex-col gap-0.5">
            <span className="text-xs font-semibold text-slate-200">Interactive Logic Topology</span>
            <span className="text-[10px] text-slate-500">Drag nodes to rearrange. Scroll to zoom. Click canvas to deselect.</span>
          </div>
          
          <div className="flex items-center gap-4 text-xs">
            <div className="flex items-center gap-1.5 font-medium text-slate-400">
              <span>Min Packet Volume:</span>
              <span className="font-mono text-cyan-400 font-bold">{minPacketVolume}</span>
            </div>
            <input
              type="range"
              min="1"
              max="20"
              value={minPacketVolume}
              onChange={(e) => setMinPacketVolume(parseInt(e.target.value))}
              className="w-24 h-1 bg-slate-900 rounded-lg appearance-none cursor-pointer accent-cyan-500"
            />
          </div>
        </div>

        <div className="bg-slate-950 border border-slate-900 rounded-lg overflow-hidden h-[450px]">
          <svg ref={svgRef} className="w-full h-full"></svg>
        </div>

        {/* Legend */}
        <div className="flex flex-wrap items-center gap-5 text-[10px] font-mono text-slate-400 border-t border-slate-900/60 pt-3">
          <span className="text-slate-500 font-bold uppercase tracking-wider">Topology Key:</span>
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 bg-cyan-500 rounded-full inline-block"></span>
            <span>Client Endpoints</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 bg-emerald-500 rounded-full inline-block"></span>
            <span>Target Servers / Gateways</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 bg-orange-500 rounded-full inline-block"></span>
            <span>Lossy Nodes (SLA Drops)</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 bg-rose-500 rounded-full inline-block animate-pulse"></span>
            <span>At-Risk Attacker / Compromise</span>
          </div>
          <div className="flex items-center gap-1.5 ml-auto">
            <span className="w-4 h-0.5 bg-red-500 inline-block"></span>
            <span>SLA Packet Drops Edge</span>
          </div>
        </div>
      </div>

      {/* Forensic Side Inspector */}
      <div className="xl:col-span-1 bg-slate-900/20 border border-slate-900 rounded-xl p-5 flex flex-col gap-4">
        <div className="border-b border-slate-900 pb-3">
          <span className="text-xs font-semibold text-slate-200 uppercase tracking-wider block">Flow & Node Inspector</span>
          <span className="text-[10px] text-slate-500">Click a node or edge to inspect session statistics.</span>
        </div>

        {selectedNode && (
          <div className="flex flex-col gap-4 text-xs font-mono text-slate-300">
            <div className="flex flex-col gap-1 border-b border-slate-900 pb-2">
              <span className="text-[9px] text-slate-500 font-bold uppercase">Node Target IP</span>
              <span className="text-cyan-400 font-bold text-sm select-all">{selectedNode.id}</span>
              <span className="text-[9px] text-slate-400">
                {selectedNode.isServer && "Host Server Daemon Role"}
                {selectedNode.isAttackerOrRisk && "SOC Compromised Leak Host"}
                {!selectedNode.isServer && !selectedNode.isAttackerOrRisk && "Standard Subnet Endpoint"}
              </span>
            </div>

            <div className="flex flex-col gap-1.5">
              <div className="flex justify-between border-b border-slate-900/40 py-1">
                <span className="text-slate-500">Packets Sent:</span>
                <span className="text-slate-100 font-bold tabular-nums">{selectedNode.packetsSent} pkts</span>
              </div>
              <div className="flex justify-between border-b border-slate-900/40 py-1">
                <span className="text-slate-500">Packets Recv:</span>
                <span className="text-slate-100 font-bold tabular-nums">{selectedNode.packetsRecv} pkts</span>
              </div>
              <div className="flex justify-between border-b border-slate-900/40 py-1">
                <span className="text-slate-500">Traffic volume:</span>
                <span className="text-slate-100 font-bold tabular-nums">{(selectedNode.totalBytes / 1024).toFixed(2)} KB</span>
              </div>
              <div className="flex justify-between border-b border-slate-900/40 py-1">
                <span className="text-slate-500">Dropped segments:</span>
                <span className={`font-bold tabular-nums ${selectedNode.totalLoss > 0 ? 'text-red-400' : 'text-slate-300'}`}>{selectedNode.totalLoss} segment drops</span>
              </div>
            </div>

            {selectedNode.isAttackerOrRisk && (
              <div className="bg-red-500/10 border border-red-500/25 p-3 rounded text-[10px] text-red-400 font-sans leading-relaxed mt-2 uppercase tracking-wide font-semibold">
                ⚠️ Lateral Threat Warning: This node transmitted raw unencrypted login passwords inside insecure application payloads. Recommend immediate quarantine.
              </div>
            )}
            
            {selectedNode.totalLoss > 5 && (
              <div className="bg-orange-500/10 border border-orange-500/25 p-3 rounded text-[10px] text-orange-400 font-sans leading-relaxed mt-2 uppercase tracking-wide font-semibold">
                ⚠️ Network Bottleneck: Extreme packet loss occurred on streams linking this client. Check for MTU blackholes or bufferbloat congestion.
              </div>
            )}
          </div>
        )}

        {selectedEdge && (
          <div className="flex flex-col gap-4 text-xs font-mono text-slate-300">
            <div className="flex flex-col gap-1 border-b border-slate-900 pb-2">
              <span className="text-[9px] text-slate-500 font-bold uppercase">Packet Flow Edge</span>
              <span className="text-slate-200 font-bold text-[10px] select-all">{selectedEdge.source.id} &rarr; {selectedEdge.target.id}</span>
            </div>

            <div className="flex flex-col gap-1.5">
              <div className="flex justify-between border-b border-slate-900/40 py-1">
                <span className="text-slate-500">Frame Count:</span>
                <span className="text-slate-100 font-bold tabular-nums">{selectedEdge.packets} packets</span>
              </div>
              <div className="flex justify-between border-b border-slate-900/40 py-1">
                <span className="text-slate-500">Bytes Transmitted:</span>
                <span className="text-slate-100 font-bold tabular-nums">{(selectedEdge.value / 1024).toFixed(2)} KB</span>
              </div>
              <div className="flex justify-between border-b border-slate-900/40 py-1">
                <span className="text-slate-500">Drops (Retrans):</span>
                <span className={`font-bold tabular-nums ${selectedEdge.retransmissions > 0 ? 'text-red-400' : 'text-slate-300'}`}>{selectedEdge.retransmissions} segments</span>
              </div>
              <div className="flex justify-between border-b border-slate-900/40 py-1">
                <span className="text-slate-500">Flow Loss Rate:</span>
                <span className={`font-bold tabular-nums ${selectedEdge.retransmissionRate > 1.0 ? 'text-red-400' : 'text-emerald-400'}`}>{selectedEdge.retransmissionRate.toFixed(2)}%</span>
              </div>
            </div>

            {selectedEdge.retransmissions > 0 && (
              <div className="bg-red-500/10 border border-red-500/25 p-3 rounded text-[10px] text-red-400 font-sans leading-relaxed mt-2 uppercase tracking-wide font-semibold">
                ⚠️ Connection SLA Breached: Retransmission rate is {selectedEdge.retransmissionRate.toFixed(2)}% (safe threshold &lt; 1.00%). Intermediate links are dropping packets under congestion load.
              </div>
            )}
          </div>
        )}

        {!selectedNode && !selectedEdge && (
          <div className="text-center py-16 text-slate-500 italic text-[11px]">
            No node or link selected. Click any circle or connection line in the graph to run diagnostics.
          </div>
        )}
      </div>
    </div>
  );
}

interface DnsChordDiagramProps {
  anomalies: NetworkPacket[];
}

function DnsChordDiagram({ anomalies }: DnsChordDiagramProps) {
  const svgRef = useRef<SVGSVGElement | null>(null);

  useEffect(() => {
    if (!svgRef.current) return;
    const svg = d3.select(svgRef.current);
    svg.selectAll('*').remove();

    if (!anomalies || anomalies.length === 0) {
      return;
    }

    // Extract unique clients and domains
    const clientsSet = new Set<string>();
    const domainsSet = new Set<string>();

    anomalies.forEach((pkt) => {
      if (pkt.srcIp) clientsSet.add(pkt.srcIp);
      if (pkt.dnsQuery?.domain) domainsSet.add(pkt.dnsQuery.domain);
    });

    const clients = Array.from(clientsSet);
    const domains = Array.from(domainsSet);
    const nodes = [...clients, ...domains];
    const N = nodes.length;

    // Create adjacency square matrix
    const matrix: number[][] = Array.from({ length: N }, () => Array(N).fill(0));

    anomalies.forEach((pkt) => {
      const clientIdx = nodes.indexOf(pkt.srcIp);
      const domainIdx = nodes.indexOf(pkt.dnsQuery?.domain || '');

      if (clientIdx !== -1 && domainIdx !== -1) {
        // Populate symmetric relationship weights
        matrix[clientIdx][domainIdx] += 1;
        matrix[domainIdx][clientIdx] += 1;
      }
    });

    // Dimensions
    const width = 500;
    const height = 280;
    const outerRadius = Math.min(width, height) * 0.5 - 55;
    const innerRadius = outerRadius - 8;

    svg.attr('viewBox', `0 0 ${width} ${height}`);

    const g = svg.append('g')
      .attr('transform', `translate(${width / 2}, ${height / 2})`);

    // Chord Layout
    const chord = d3.chord()
      .padAngle(0.06)
      .sortSubgroups(d3.descending)(matrix);

    const arc = d3.arc<any, d3.ChordGroup>()
      .innerRadius(innerRadius)
      .outerRadius(outerRadius);

    const ribbon = d3.ribbon<any, d3.Chord>()
      .radius(innerRadius);

    const isClient = (idx: number) => idx < clients.length;

    // Inner Ribbons / Chords
    g.append('g')
      .attr('fill-opacity', 0.3)
      .selectAll('path')
      .data(chord)
      .join('path')
      .attr('d', ribbon)
      .attr('fill', d => isClient(d.source.index) ? '#06b6d4' : '#ef4444')
      .attr('stroke', d => isClient(d.source.index) ? '#06b6d4' : '#ef4444')
      .attr('stroke-width', 0.5)
      .style('mix-blend-mode', 'screen')
      .append('title')
      .text(d => `${nodes[d.source.index]} ↔ ${nodes[d.target.index]} (${matrix[d.source.index][d.target.index]} queries)`);

    // Outer Arc Nodes
    const group = g.append('g')
      .selectAll('g')
      .data(chord.groups)
      .join('g');

    group.append('path')
      .attr('fill', d => isClient(d.index) ? '#06b6d4' : '#ef4444')
      .attr('stroke', d => isClient(d.index) ? '#22d3ee' : '#f87171')
      .attr('stroke-width', 1)
      .attr('d', arc)
      .append('title')
      .text(d => `${nodes[d.index]} (${isClient(d.index) ? 'Client IP' : 'Broken Endpoint Domain'})`);

    // Radially Rotated Labels
    group.append('text')
      .each((d: any) => { d.angle = (d.startAngle + d.endAngle) / 2; })
      .attr('dy', '.35em')
      .attr('transform', (d: any) => `
        rotate(${(d.angle * 180 / Math.PI - 90)})
        translate(${outerRadius + 8})
        ${d.angle > Math.PI ? 'rotate(180)' : ''}
      `)
      .attr('text-anchor', (d: any) => d.angle > Math.PI ? 'end' : 'start')
      .text(d => {
        const name = nodes[d.index];
        return name.length > 20 ? name.substring(0, 17) + '...' : name;
      })
      .style('fill', '#64748b')
      .style('font-family', 'var(--font-mono, monospace)')
      .style('font-size', '8px')
      .style('font-weight', '500');

  }, [anomalies]);

  return (
    <div className="flex flex-col gap-3 p-4 bg-slate-950 border border-slate-900 rounded-lg overflow-hidden">
      <div className="flex items-center justify-between text-xs text-slate-400 font-medium border-b border-slate-900 pb-2">
        <div className="flex items-center gap-2">
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 bg-cyan-500 rounded-full inline-block"></span>
            <span>Resolver Clients</span>
          </div>
          <div className="flex items-center gap-1.5 ml-3">
            <span className="w-2.5 h-2.5 bg-red-500 rounded-full inline-block animate-pulse"></span>
            <span className="text-red-400">Target Failing Domains</span>
          </div>
        </div>
        <span className="text-[10px] font-mono text-slate-500">D3.js Resolution Chord</span>
      </div>
      <div className="flex justify-center items-center py-2 bg-slate-950">
        <svg ref={svgRef} className="w-full max-w-[460px] h-auto max-h-[260px]"></svg>
      </div>
    </div>
  );
}

function generateHexDump(infoText: string, pkt: any): string {
  const bytes: number[] = [];

  // Add dummy Ethernet + IP + TCP headers for visual realism
  bytes.push(0x00, 0x11, 0x22, 0x33, 0x44, 0x55);
  bytes.push(0x00, 0x50, 0x56, 0xc0, 0x00, 0x08);
  bytes.push(0x08, 0x00); // IPv4

  // IPv4 Header
  bytes.push(0x45, 0x00, 0x00, 0x00, 0x1a, 0x2b, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00);
  
  // Source IP (parse octets)
  const srcOctets = (pkt.srcIp || '127.0.0.1').split('.').map((o: string) => parseInt(o) || 0);
  while (srcOctets.length < 4) srcOctets.push(0);
  bytes.push(...srcOctets);

  // Destination IP
  const dstOctets = (pkt.dstIp || '127.0.0.1').split('.').map((o: string) => parseInt(o) || 0);
  while (dstOctets.length < 4) dstOctets.push(0);
  bytes.push(...dstOctets);

  // TCP or UDP header
  if (pkt.protocol === 'UDP' || pkt.protocol === 'DNS') {
    const srcPort = pkt.srcPort || 53;
    const dstPort = pkt.dstPort || 53;
    bytes.push((srcPort >> 8) & 0xff, srcPort & 0xff);
    bytes.push((dstPort >> 8) & 0xff, dstPort & 0xff);
    bytes.push(0x00, 0x00, 0x00, 0x00); // length + checksum
  } else {
    // TCP
    const srcPort = pkt.srcPort || 80;
    const dstPort = pkt.dstPort || 80;
    bytes.push((srcPort >> 8) & 0xff, srcPort & 0xff);
    bytes.push((dstPort >> 8) & 0xff, dstPort & 0xff);
    bytes.push(0x00, 0x00, 0x00, 0x01); // seq
    bytes.push(0x00, 0x00, 0x00, 0x01); // ack
    bytes.push(0x50, 0x10, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00); // offset, flags, window, checksum, urgent
  }

  // Payload bytes from infoText
  for (let i = 0; i < infoText.length; i++) {
    bytes.push(infoText.charCodeAt(i) & 0xff);
  }

  // Format into rows of 16 bytes
  const lines: string[] = [];
  for (let i = 0; i < bytes.length; i += 16) {
    const rowBytes = bytes.slice(i, i + 16);
    const offset = i.toString(16).padStart(4, '0');
    
    // Format hex section: 8 bytes, space, 8 bytes
    const hexParts: string[] = [];
    for (let j = 0; j < 16; j++) {
      if (j < rowBytes.length) {
        hexParts.push(rowBytes[j].toString(16).padStart(2, '0'));
      } else {
        hexParts.push('  ');
      }
    }
    const hexStr = hexParts.slice(0, 8).join(' ') + '  ' + hexParts.slice(8, 16).join(' ');

    // Format ASCII section
    const asciiChars: string[] = [];
    for (let j = 0; j < rowBytes.length; j++) {
      const b = rowBytes[j];
      if (b >= 32 && b <= 126) {
        asciiChars.push(String.fromCharCode(b));
      } else {
        asciiChars.push('.');
      }
    }
    const asciiStr = asciiChars.join('');

    lines.push(`${offset}  ${hexStr}  |${asciiStr}|`);
  }

  return lines.join('\n');
}

interface GlobalAlertsTickerProps {
  analysisResult: PcapAnalysisResult | null;
}

function GlobalAlertsTicker({ analysisResult }: GlobalAlertsTickerProps) {
  const [alerts, setAlerts] = React.useState<string[]>([
    "SYSTEM STATUS: Ready. Ingest a network capture file (.pcap / .pcapng) to run full-stack TAC diagnostics."
  ]);

  React.useEffect(() => {
    if (!analysisResult) {
      setAlerts([
        "SYSTEM PRE-FLIGHT: Network interface status nominal · Diagnostic engine ready to ingest packet traces."
      ]);
      return;
    }

    const list: string[] = [];

    // 1. Check Global Loss SLA Breach
    if (analysisResult.globalRetransmissionRate > 1.0) {
      list.push(
        `CRITICAL RETRANSMISSION LEVEL: Global TCP retransmission rate is at ${analysisResult.globalRetransmissionRate.toFixed(2)}% (safe threshold is < 1.00%)`
      );
    }

    // 2. High packet loss connections (Worst offenders)
    const worstConn = (analysisResult.connections || [])
      .filter((c: any) => c.retransmissionRate > 1.0 && c.retransmissions > 0)
      .sort((a, b) => b.retransmissionRate - a.retransmissionRate);

    worstConn.forEach((c) => {
      list.push(
        `WARNING: Connection packet loss of ${c.retransmissionRate.toFixed(1)}% detected on ${c.srcIp} -> ${c.dstIp} (${c.retransmissions} dropped segments)`
      );
    });

    // 3. Plaintext administrative logins
    (analysisResult.plaintextCredentials || []).forEach((cred) => {
      list.push(
        `CRITICAL SECURITY LEAK: Plaintext credentials exposed for service ${cred.plaintextCredentials?.service} (${cred.plaintextCredentials?.type}) on client ${cred.srcIp} -> ${cred.dstIp}`
      );
    });

    // 4. DNS Errors and Low TTL Hijacking/Evasion Alerts
    const lowDnsTtlSet = new Set<string>();
    (analysisResult.packets || []).forEach((p) => {
      if (p.protocol === 'DNS' && p.dnsQuery && p.dnsQuery.isResponse && p.dnsQuery.dnsTtl !== undefined) {
        if (p.dnsQuery.dnsTtl <= 10 && !lowDnsTtlSet.has(p.dnsQuery.domain)) {
          lowDnsTtlSet.add(p.dnsQuery.domain);
          list.push(
            `CRITICAL DNS HIJACKING/EVASION WARNING: Excessively low DNS TTL of ${p.dnsQuery.dnsTtl}s detected on domain '${p.dnsQuery.domain}' (possible DNS hijacking, fast-flux evasion, or subversion)`
          );
        }
      }
    });

    (analysisResult.dnsAnomalies || []).forEach((dns) => {
      list.push(
        `PROTOCOL INCIDENT: DNS Fail (${dns.dnsQuery?.rcodeName}) on client ${dns.srcIp} for query '${dns.dnsQuery?.domain}'`
      );
    });

    // 5. TTL Path anomalies
    (analysisResult.ttlAnomalies || []).forEach((anomaly) => {
      list.push(
        `ROUTING ALERT: Layer-3 path flapping or ${anomaly.type} flagged on IP ${anomaly.ip} with fluctuating TTLs (${anomaly.ttls.join(', ')})`
      );
    });

    if (list.length === 0) {
      list.push(
        "SYSTEM HEALTH NOMINAL: Packet stream parsed successfully. 0 packet loss or security incidents detected."
      );
    }

    setAlerts(list);
  }, [analysisResult]);

  return (
    <div className="bg-slate-950 border-b border-slate-900 h-9 flex items-center overflow-hidden relative select-none">
      {/* Live Alerts Header Label Badge */}
      <div className="bg-red-500/10 border-r border-slate-900 px-4 h-full flex items-center gap-2 z-10 shrink-0">
        <span className="w-2 h-2 bg-red-500 rounded-full animate-pulse"></span>
        <span className="text-[10px] font-sans font-bold tracking-wider text-red-400 uppercase whitespace-nowrap">
          Live Alerts Feed
        </span>
      </div>

      {/* Marquee Viewport */}
      <div className="flex-1 overflow-hidden h-full flex items-center relative">
        <div className="animate-marquee hover:[animation-play-state:paused] flex gap-12 text-[11px] font-mono font-medium text-slate-300 tabular-nums">
          {/* Loop 1 */}
          {alerts.map((alert, idx) => (
            <div key={`alert-1-${idx}`} className="flex items-center gap-3 shrink-0 whitespace-nowrap">
              <span className="text-cyan-500/60 font-bold">·</span>
              <span className={
                alert.includes('CRITICAL') || alert.includes('SECURITY LEAK') ? 'text-red-400 font-semibold' :
                alert.includes('WARNING') || alert.includes('ROUTING ALERT') ? 'text-amber-400 font-medium' :
                'text-slate-300'
              }>
                {alert}
              </span>
            </div>
          ))}
          {/* Loop 2 */}
          {alerts.map((alert, idx) => (
            <div key={`alert-2-${idx}`} className="flex items-center gap-3 shrink-0 whitespace-nowrap">
              <span className="text-cyan-500/60 font-bold">·</span>
              <span className={
                alert.includes('CRITICAL') || alert.includes('SECURITY LEAK') ? 'text-red-400 font-semibold' :
                alert.includes('WARNING') || alert.includes('ROUTING ALERT') ? 'text-amber-400 font-medium' :
                'text-slate-300'
              }>
                {alert}
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

export default function App() {
  // Advanced Filter Builder state
  interface FilterRule {
    id: string;
    field: string;
    operator: '==' | '!=' | 'contains' | '>' | '<';
    value: string;
  }
  const [filterRules, setFilterRules] = useState<FilterRule[]>([]);
  const [filterConnector, setFilterConnector] = useState<'AND' | 'OR'>('AND');
  const [isFilterBuilderOpen, setIsFilterBuilderOpen] = useState<boolean>(false);

  const addFilterRule = () => {
    const newRule: FilterRule = {
      id: Math.random().toString(36).substring(2, 9),
      field: 'ip.src',
      operator: '==',
      value: ''
    };
    setFilterRules([...filterRules, newRule]);
  };

  const removeFilterRule = (id: string) => {
    setFilterRules(filterRules.filter(r => r.id !== id));
  };

  const updateFilterRule = (id: string, updates: Partial<FilterRule>) => {
    setFilterRules(filterRules.map(r => r.id === id ? { ...r, ...updates } : r));
  };

  const clearFilterRules = () => {
    setFilterRules([]);
  };

  const applyFilterPreset = (presetType: 'syn_loss' | 'plaintext' | 'payment_fail') => {
    setIsFilterBuilderOpen(true);
    setFilterConnector('AND');
    switch (presetType) {
      case 'syn_loss':
        setFilterRules([
          { id: '1', field: 'tcp.flags.syn', operator: '==', value: 'true' },
          { id: '2', field: 'tcp.retransmission', operator: '==', value: 'true' }
        ]);
        break;
      case 'plaintext':
        setFilterRules([
          { id: '1', field: 'protocol', operator: '==', value: 'HTTP' },
          { id: '2', field: 'info', operator: 'contains', value: 'Authorization' }
        ]);
        break;
      case 'payment_fail':
        setFilterRules([
          { id: '1', field: 'dns.qry.name', operator: 'contains', value: 'payment' },
          { id: '2', field: 'dns.rcode', operator: '!=', value: '0' }
        ]);
        break;
    }
  };

  const evaluateFilterRules = (pkt: NetworkPacket): boolean => {
    if (filterRules.length === 0) return true;

    const results = filterRules.map(rule => {
      let val: any = undefined;

      switch (rule.field) {
        case 'ip.src': val = pkt.srcIp; break;
        case 'ip.dst': val = pkt.dstIp; break;
        case 'ip.len': val = pkt.length; break;
        case 'ip.ttl': val = pkt.ttl; break;
        case 'tcp.srcport': val = pkt.srcPort; break;
        case 'tcp.dstport': val = pkt.dstPort; break;
        case 'tcp.flags.syn': val = pkt.tcpFlags?.syn; break;
        case 'tcp.flags.ack': val = pkt.tcpFlags?.ack; break;
        case 'tcp.flags.fin': val = pkt.tcpFlags?.fin; break;
        case 'tcp.flags.rst': val = pkt.tcpFlags?.rst; break;
        case 'tcp.flags.psh': val = pkt.tcpFlags?.psh; break;
        case 'tcp.retransmission': val = pkt.isRetransmission; break;
        case 'dns.qry.name': val = pkt.dnsQuery?.domain; break;
        case 'dns.rcode': val = pkt.dnsQuery?.rcode; break;
        case 'protocol': val = pkt.protocol; break;
        case 'info': val = pkt.info; break;
        default: break;
      }

      if (val === undefined) return false;

      const ruleValue = rule.value.trim().toLowerCase();
      const pktValueStr = String(val).toLowerCase();

      switch (rule.operator) {
        case '==':
          if (ruleValue === 'true') return val === true;
          if (ruleValue === 'false') return val === false;
          return pktValueStr === ruleValue;
        case '!=':
          if (ruleValue === 'true') return val !== true;
          if (ruleValue === 'false') return val !== false;
          return pktValueStr !== ruleValue;
        case 'contains':
          return pktValueStr.includes(ruleValue);
        case '>':
          return Number(val) > Number(rule.value);
        case '<':
          return Number(val) < Number(rule.value);
        default:
          return false;
      }
    });

    if (filterConnector === 'AND') {
      return results.every(r => r === true);
    } else {
      return results.some(r => r === true);
    }
  };

  // Navigation tabs
  const [activeTab, setActiveTab] = useState<'dashboard' | 'packets' | 'security' | 'dns' | 'batch' | 'topology' | 'latency' | 'middlebox' | 'tls' | 'correlation' | 'asymmetric' | 'microburst' | 'shadow_iot' | 'radius' | 'overlay' | 'routing' | 'voip'>('dashboard');

  // Dual-Capture Ingress vs. Egress Correlation states
  const [ingressResult, setIngressResult] = useState<PcapAnalysisResult | null>(null);
  const [egressResult, setEgressResult] = useState<PcapAnalysisResult | null>(null);
  const [ingressFileName, setIngressFileName] = useState<string>('');
  const [egressFileName, setEgressFileName] = useState<string>('');
  const [isCorrelating, setIsCorrelating] = useState(false);
  const [correlationTable, setCorrelationTable] = useState<Array<{
    ipId: number;
    tcpSeq: number;
    ingressTime: number;
    srcIp: string;
    dstIp: string;
    srcPort?: number;
    dstPort?: number;
    length: number;
    verdict: string;
  }>>([]);

  // Batch comparison states
  const [batchResults, setBatchResults] = useState<Array<{ id: string; fileName: string; result: PcapAnalysisResult }>>([]);
  const [isBatchAiAnalyzing, setIsBatchAiAnalyzing] = useState<boolean>(false);
  const [batchRcaReport, setBatchRcaReport] = useState<string | null>(null);
  const [batchCustomContext, setBatchCustomContext] = useState<string>('');

  // Loading states
  const [isParsing, setIsParsing] = useState<boolean>(false);
  const [isAiAnalyzing, setIsAiAnalyzing] = useState<boolean>(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  // Analysis state
  const [analysisResult, setAnalysisResult] = useState<PcapAnalysisResult | null>(null);
  const [loadedScenario, setLoadedScenario] = useState<string | null>(null);
  const [uploadedPcapBase64, setUploadedPcapBase64] = useState<string | null>(null);

  // AI Context steering
  const [customContext, setCustomContext] = useState('');
  const [rcaReport, setRcaReport] = useState<string | null>(null);

  // Packet view filters
  const [searchTerm, setSearchTerm] = useState('');
  const [protocolFilter, setProtocolFilter] = useState('ALL');
  const [expandedPacketIndex, setExpandedPacketIndex] = useState<number | null>(null);

  // Firewall vendor debug states
  const [firewallVendor, setFirewallVendor] = useState<'palo_alto' | 'fortinet'>('palo_alto');
  const [copiedText, setCopiedText] = useState(false);
  const [microburstCapacity, setMicroburstCapacity] = useState<number>(100);

  // Threat-to-Code IDS Rule Synthesizer states
  interface IdsRuleResult {
    ruleTitle: string;
    suricataRule: string;
    sigmaRule: string;
    threatSeverity: string;
    targetProtocol?: string;
    signatureExplanation: string;
    mitreAttackMapping?: string;
    layerBreakdown?: {
      l3: string;
      l4: string;
      l7: string;
    };
  }

  const [idsModalOpen, setIdsModalOpen] = useState(false);
  const [idsLoading, setIdsLoading] = useState(false);
  const [idsActivePacket, setIdsActivePacket] = useState<NetworkPacket | null>(null);
  const [idsRuleResult, setIdsRuleResult] = useState<IdsRuleResult | null>(null);
  const [idsError, setIdsError] = useState<string | null>(null);
  const [copiedSuricata, setCopiedSuricata] = useState(false);
  const [copiedSigma, setCopiedSigma] = useState(false);
  const [copiedAllRules, setCopiedAllRules] = useState(false);

  // VoIP & Telephony states
  const [selectedVoipCallId, setSelectedVoipCallId] = useState<string | null>(null);
  const [voipStatusFilter, setVoipStatusFilter] = useState<'all' | 'failed' | 'nominal'>('all');
  const [voipSearchQuery, setVoipSearchQuery] = useState<string>('');
  const [copiedVoipScript, setCopiedVoipScript] = useState(false);
  const [copiedCallId, setCopiedCallId] = useState<string | null>(null);

  const voipPythonScriptContent = `\"\"\"
AutoTAC Telephony Diagnostics Engine: VoIP & SIP/RTP Quality Analyzer
=====================================================================
Automated detection of enterprise SIP signaling failures (4xx, 5xx, 6xx)
and RTP packet loss degradation causing voice jitter and robotic audio.
\"\"\"

import streamlit as st
import pandas as pd
from scapy.all import rdpcap, UDP, TCP, IP, Raw
import re

st.set_page_config(page_title="AutoTAC - Voice & Telephony Health", layout="wide")
st.title("📞 AutoTAC: Voice & Telephony Health")

# 1. SIP Logic: Filter for SIP (UDP/TCP 5060) & Extract Status Codes
def parse_sip(payload):
    try:
        text = payload.decode('utf-8', errors='ignore')
    except Exception:
        return None
    lines = text.split('\\r\\n') if '\\r\\n' in text else text.split('\\n')
    if not lines or not lines[0]: return None
    first = lines[0].strip()
    is_res = first.startswith('SIP/2.0')
    code, text_status = None, ""
    if is_res:
        parts = first.split(' ', 2)
        if len(parts) >= 2 and parts[1].isdigit():
            code = int(parts[1])
            text_status = parts[2] if len(parts) > 2 else ""
    call_id, caller, callee = "", "Anonymous", "Unknown"
    for l in lines[1:]:
        if re.match(r'^Call-ID:\\s*', l, re.I): call_id = re.sub(r'^Call-ID:\\s*', '', l, flags=re.I).strip()
        elif re.match(r'^From:\\s*', l, re.I): caller = re.sub(r'^From:\\s*', '', l, flags=re.I).strip()
        elif re.match(r'^To:\\s*', l, re.I): callee = re.sub(r'^To:\\s*', '', l, flags=re.I).strip()
    return {"call_id": call_id, "caller": caller, "callee": callee, "code": code, "text": text_status, "is_res": is_res}

# 2. RTP Logic: Filter RTP Streams & Calculate Packet Loss %
def analyze_pcap(path):
    packets = rdpcap(path)
    sip_calls, rtp_streams = {}, {}
    for p in packets:
        if not p.haslayer(IP): continue
        # SIP Filter (5060)
        if (p.haslayer(UDP) and (p[UDP].sport == 5060 or p[UDP].dport == 5060)) or \\
           (p.haslayer(TCP) and (p[TCP].sport == 5060 or p[TCP].dport == 5060)):
            if p.haslayer(Raw):
                s = parse_sip(p[Raw].load)
                if s and s["call_id"]:
                    cid = s["call_id"]
                    if cid not in sip_calls:
                        sip_calls[cid] = {"Caller": s["caller"], "Callee": s["callee"], "Call-ID": cid, "SIP Status": "Initiated"}
                    if s["is_res"] and s["code"]:
                        c = s["code"]
                        if 400 <= c < 500: sip_calls[cid]["SIP Status"] = f"⚠️ {c} {s['text']} (Client Error)"
                        elif 500 <= c < 600: sip_calls[cid]["SIP Status"] = f"🚨 {c} {s['text']} (Server Error)"
                        elif 600 <= c <= 699: sip_calls[cid]["SIP Status"] = f"🛑 {c} {s['text']} (Global Failure)"
                        else: sip_calls[cid]["SIP Status"] = f"✅ {c} {s['text']}"
        # RTP Filter (UDP payload V=2)
        if p.haslayer(UDP) and p.haslayer(Raw) and p[UDP].sport != 5060 and p[UDP].dport != 5060:
            b = p[Raw].load
            if len(b) >= 12 and (b[0] & 0xC0) == 0x80:
                seq = int.from_bytes(b[2:4], 'big')
                ssrc = int.from_bytes(b[8:12], 'big')
                rtp_streams.setdefault(ssrc, []).append(seq)

    max_loss = 0.0
    for ssrc, seqs in rtp_streams.items():
        exp = max(seqs) - min(seqs) + 1
        rec = len(seqs)
        pct = (max(0, exp - rec) / exp * 100.0) if exp > 0 else 0.0
        if pct > max_loss: max_loss = pct
    return list(sip_calls.values()), max_loss

# 3. Streamlit UI: "Voice & Telephony Health" tab
tab_voip, = st.tabs(["Voice & Telephony Health"])
with tab_voip:
    st.subheader("📞 Voice & Telephony Health")
    calls, max_rtp_loss = analyze_pcap("capture.pcap")

    # 4. Output: Render active SIP Calls table [Caller, Callee, Call-ID, SIP Status]
    st.dataframe(pd.DataFrame(calls)[["Caller", "Callee", "Call-ID", "SIP Status"]], use_container_width=True)

    # 4. Output: Warning metric card showing "Max RTP Packet Loss %"
    if max_rtp_loss >= 3.0:
        st.metric(label="Max RTP Packet Loss %", value=f"{max_rtp_loss:.1f}%", delta="-High Loss", delta_color="inverse")
        st.warning(f"⚠️ Warning: Severe voice jitter or robotic audio detected ({max_rtp_loss:.1f}% packet loss)!")
    else:
        st.metric(label="Max RTP Packet Loss %", value=f"{max_rtp_loss:.1f}%")
`;

  const handleCopyCallId = (callId: string) => {
    navigator.clipboard.writeText(callId);
    setCopiedCallId(callId);
    setTimeout(() => setCopiedCallId(null), 2000);
  };

  const getPacketAnomalyBadge = (pkt: NetworkPacket): { label: string; color: string; isAnomaly: boolean } | null => {
    if (pkt.plaintextCredentials) {
      return { label: `LEAK: ${pkt.plaintextCredentials.service}`, color: 'bg-red-500/15 text-red-300 border-red-500/30', isAnomaly: true };
    }
    if (pkt.tlsAlertCode !== undefined) {
      return { label: `TLS ALERT: 0x${pkt.tlsAlertCode.toString(16)}`, color: 'bg-rose-500/15 text-rose-300 border-rose-500/30', isAnomaly: true };
    }
    if (pkt.dnsQuery && pkt.dnsQuery.isResponse && pkt.dnsQuery.rcode !== undefined && pkt.dnsQuery.rcode !== 0) {
      return { label: `DNS: ${pkt.dnsQuery.rcodeName || 'ERROR'}`, color: 'bg-purple-500/15 text-purple-300 border-purple-500/30', isAnomaly: true };
    }
    if (pkt.radiusData && pkt.radiusData.code === 3) {
      return { label: 'RADIUS REJECT', color: 'bg-red-500/15 text-red-300 border-red-500/30', isAnomaly: true };
    }
    if (pkt.overlayData?.isUnencrypted) {
      return { label: 'UNENCRYPTED OVERLAY', color: 'bg-amber-500/15 text-amber-300 border-amber-500/30', isAnomaly: true };
    }
    if (pkt.bgpData?.type === 3) {
      return { label: 'BGP NOTIF DROP', color: 'bg-red-500/15 text-red-300 border-red-500/30', isAnomaly: true };
    }
    if (pkt.ospfData?.type === 2 && pkt.ospfData.ospfMtu !== undefined) {
      return { label: `OSPF DBD MTU: ${pkt.ospfData.ospfMtu}B`, color: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30', isAnomaly: true };
    }
    if (pkt.sipData && pkt.sipData.isResponse && pkt.sipData.statusCode && pkt.sipData.statusCode >= 400) {
      return { label: `SIP ${pkt.sipData.statusCode} ERROR`, color: 'bg-red-500/15 text-red-300 border-red-500/30', isAnomaly: true };
    }
    if (pkt.isRetransmission) {
      return { label: 'RETRANSMISSION', color: 'bg-orange-500/15 text-orange-300 border-orange-500/30', isAnomaly: true };
    }
    return null;
  };

  const handleGenerateIdsRule = async (pkt: NetworkPacket) => {
    const anomaly = getPacketAnomalyBadge(pkt);
    const anomalyReason = anomaly
      ? `Flagged network anomaly: ${anomaly.label}. Protocol: ${pkt.protocol}, Payload Info: ${pkt.info}`
      : `Detected packet anomaly on ${pkt.srcIp}:${pkt.srcPort || 'any'} -> ${pkt.dstIp}:${pkt.dstPort || 'any'}. Info: ${pkt.info}`;

    setIdsActivePacket(pkt);
    setIdsRuleResult(null);
    setIdsError(null);
    setIdsLoading(true);
    setIdsModalOpen(true);
    setCopiedSuricata(false);
    setCopiedSigma(false);
    setCopiedAllRules(false);

    try {
      const res = await fetch('/api/gemini/generate-ids-rule', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ packet: pkt, anomalyReason })
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.error || `Server responded with status ${res.status}`);
      }

      const data: IdsRuleResult = await res.json();
      setIdsRuleResult(data);
    } catch (err: any) {
      console.error('Failed to generate IDS rule:', err);
      setIdsError(err.message || 'Failed to synthesize intrusion detection rule.');
    } finally {
      setIdsLoading(false);
    }
  };

  const copySuricataRule = () => {
    if (!idsRuleResult?.suricataRule) return;
    navigator.clipboard.writeText(idsRuleResult.suricataRule);
    setCopiedSuricata(true);
    setTimeout(() => setCopiedSuricata(false), 2000);
  };

  const copySigmaRule = () => {
    if (!idsRuleResult?.sigmaRule) return;
    navigator.clipboard.writeText(idsRuleResult.sigmaRule);
    setCopiedSigma(true);
    setTimeout(() => setCopiedSigma(false), 2000);
  };

  const copyAllRules = () => {
    if (!idsRuleResult) return;
    const fullText = `# AUTO-TAC THREAT-TO-CODE DETECTION RULES\n# Title: ${idsRuleResult.ruleTitle}\n# Severity: ${idsRuleResult.threatSeverity}\n# MITRE ATT&CK: ${idsRuleResult.mitreAttackMapping || 'N/A'}\n\n# --- SURICATA IDS RULE ---\n${idsRuleResult.suricataRule}\n\n# --- SIEM SIGMA RULE ---\n${idsRuleResult.sigmaRule}\n`;
    navigator.clipboard.writeText(fullText);
    setCopiedAllRules(true);
    setTimeout(() => setCopiedAllRules(false), 2000);
  };

  const downloadFile = (filename: string, content: string, mime: string) => {
    const blob = new Blob([content], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  // Backend status polling
  const [backendStatus, setBackendStatus] = useState<{
    online: boolean;
    uptime?: number;
    memoryUsage?: number;
    engineState: 'idle' | 'analyzing' | 'offline';
  }>({ online: false, engineState: 'offline' });

  useEffect(() => {
    const checkStatus = async () => {
      try {
        const res = await fetch('/api/status');
        if (res.ok) {
          const data = await res.json();
          setBackendStatus({
            online: true,
            uptime: data.uptime,
            memoryUsage: data.memoryUsage,
            engineState: isParsing || isAiAnalyzing ? 'analyzing' : 'idle'
          });
        } else {
          setBackendStatus({ online: false, engineState: 'offline' });
        }
      } catch {
        setBackendStatus({ online: false, engineState: 'offline' });
      }
    };

    checkStatus();
    const timer = setInterval(checkStatus, 5000);
    return () => clearInterval(timer);
  }, [isParsing, isAiAnalyzing]);

  // Re-trigger background analysis engine task
  const handleReTriggerAnalysis = async () => {
    setIsParsing(true);
    setErrorMsg(null);
    setRcaReport(null);
    try {
      let data: PcapAnalysisResult;
      if (loadedScenario) {
        const res = await fetch('/api/analyze-pcap', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ scenarioId: loadedScenario })
        });
        if (!res.ok) throw new Error('Failed to parse preset scenario packet capture.');
        data = await res.json();
      } else if (uploadedPcapBase64) {
        const res = await fetch('/api/analyze-pcap', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ pcapBase64: uploadedPcapBase64 })
        });
        if (!res.ok) throw new Error('Failed to re-parse uploaded packet capture.');
        data = await res.json();
      } else {
        throw new Error('No active packet capture trace to re-run analysis on.');
      }

      setAnalysisResult(data);
      triggerAiRca(data);
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to re-run analysis task.');
    } finally {
      setIsParsing(false);
    }
  };

  // Load a scenario by default on first load so the app is instantly rich with data!
  useEffect(() => {
    handleLoadScenario('congestion_retransmission');
  }, []);

  // One-click load preset scenario
  const handleLoadScenario = async (scenarioId: string) => {
    setIsParsing(true);
    setErrorMsg(null);
    setLoadedScenario(scenarioId);
    setUploadedPcapBase64(null); // Clear uploaded file on scenario change
    setRcaReport(null); // Clear old report
    try {
      const res = await fetch('/api/analyze-pcap', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scenarioId })
      });

      if (!res.ok) {
        throw new Error('Failed to parse preset scenario packet capture.');
      }

      const data: PcapAnalysisResult = await res.json();
      setAnalysisResult(data);

      // Instantly trigger AI RCA generation for the scenario to make it fully populated!
      triggerAiRca(data);
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to process capture file.');
    } finally {
      setIsParsing(false);
    }
  };

  // Helper to parse a single PCAP/PCAPNG file using existing server endpoint
  const parsePcapFile = (file: File): Promise<PcapAnalysisResult> => {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = async (event) => {
        try {
          const arrayBuffer = event.target?.result as ArrayBuffer;
          if (!arrayBuffer) {
            throw new Error('Could not read upload file buffer.');
          }

          // Convert raw binary array buffer to Base64
          const uint8Array = new Uint8Array(arrayBuffer);
          let binaryString = '';
          const chunkSize = 8192;
          for (let i = 0; i < uint8Array.length; i += chunkSize) {
            binaryString += String.fromCharCode.apply(
              null,
              Array.from(uint8Array.subarray(i, i + chunkSize))
            );
          }
          const pcapBase64 = btoa(binaryString);
          setUploadedPcapBase64(pcapBase64); // Save base64 in state for re-runs & filtered downloads!

          const res = await fetch('/api/analyze-pcap', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ pcapBase64 })
          });

          if (!res.ok) {
            throw new Error(`Server parsing failed for file: ${file.name}`);
          }

          const data: PcapAnalysisResult = await res.json();
          resolve(data);
        } catch (err) {
          reject(err);
        }
      };
      reader.onerror = () => reject(new Error('FileReader read error'));
      reader.readAsArrayBuffer(file);
    });
  };

  // Upload custom local PCAP files (supports multiple PCAP uploads simultaneously)
  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files;
    if (!files || files.length === 0) return;

    setIsParsing(true);
    setErrorMsg(null);

    // If uploading multiple files
    if (files.length > 1) {
      setLoadedScenario(null);
      setRcaReport(null);
      try {
        const resultsArray: Array<{ id: string; fileName: string; result: PcapAnalysisResult }> = [];
        for (let i = 0; i < files.length; i++) {
          const file = files[i];
          const result = await parsePcapFile(file);
          resultsArray.push({
            id: Math.random().toString(36).substring(2, 9),
            fileName: file.name,
            result
          });
        }
        setBatchResults(resultsArray);
        
        // Load the first PCAP in the stream view for easy individual toggling
        setAnalysisResult(resultsArray[0].result);
        setActiveTab('batch');
        triggerBatchAiRca(resultsArray);
      } catch (err: any) {
        setErrorMsg(err.message || 'Error occurred during batch file processing.');
      } finally {
        setIsParsing(false);
      }
      return;
    }

    // Standard single-file upload
    const file = files[0];
    setLoadedScenario(null);
    setRcaReport(null);

    try {
      const data = await parsePcapFile(file);
      setAnalysisResult(data);
      // Add to batch list as well for easy comparison
      setBatchResults([{
        id: Math.random().toString(36).substring(2, 9),
        fileName: file.name,
        result: data
      }]);
      triggerAiRca(data);
    } catch (err: any) {
      setErrorMsg(err.message || 'Error occurred during file processing.');
    } finally {
      setIsParsing(false);
    }
  };

  // Call Gemini to generate technical Batch comparison report
  const triggerBatchAiRca = async (captures: Array<{ fileName: string; result: PcapAnalysisResult }>, overrideContext?: string) => {
    setIsBatchAiAnalyzing(true);
    setBatchRcaReport(null);
    try {
      const res = await fetch('/api/gemini/analyze-batch', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          batchCaptures: captures.map(c => ({ fileName: c.fileName, result: c.result })),
          customInstruction: overrideContext || batchCustomContext
        })
      });

      if (!res.ok) {
        throw new Error('Failed to retrieve batch comparison recommendation from Gemini.');
      }

      const data = await res.json();
      setBatchRcaReport(data.batchReport || 'No recommendation returned.');
    } catch (err: any) {
      setBatchRcaReport(`[TAC Engine Error] Failed to generate Batch AI Comparison: ${err.message}`);
    } finally {
      setIsBatchAiAnalyzing(false);
    }
  };

  const handleUpdateBatchRcaContext = (e: React.FormEvent) => {
    e.preventDefault();
    if (batchResults.length === 0) return;
    triggerBatchAiRca(batchResults, batchCustomContext);
  };

  // Load preset batch comparison scenario (converts pre-built scenarios into a single batch list instantly)
  const handleLoadBatchPreset = async () => {
    setIsParsing(true);
    setErrorMsg(null);
    setBatchRcaReport(null);
    try {
      const presets = [
        { id: 'congestion_retransmission', name: 'hospital_db_drops.pcap' },
        { id: 'dns_outage', name: 'dns_daemon_crash.pcap' },
        { id: 'plaintext_credentials', name: 'credentials_leak.pcap' }
      ];

      const resultsArray: Array<{ id: string; fileName: string; result: PcapAnalysisResult }> = [];
      
      for (const p of presets) {
        const res = await fetch('/api/analyze-pcap', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ scenarioId: p.id })
        });
        if (!res.ok) {
          throw new Error(`Failed to parse preset scenario: ${p.id}`);
        }
        const result: PcapAnalysisResult = await res.json();
        resultsArray.push({
          id: p.id,
          fileName: p.name,
          result
        });
      }

      setBatchResults(resultsArray);
      setAnalysisResult(resultsArray[0].result);
      setActiveTab('batch');
      triggerBatchAiRca(resultsArray);
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to process batch preset captures.');
    } finally {
      setIsParsing(false);
    }
  };

  // Call Gemini to generate technical RCA
  const triggerAiRca = async (resultToAnalyze: PcapAnalysisResult, overrideContext?: string) => {
    setIsAiAnalyzing(true);
    setRcaReport(null);
    try {
      const res = await fetch('/api/gemini/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          analysisResult: resultToAnalyze,
          customInstruction: overrideContext || customContext
        })
      });

      if (!res.ok) {
        throw new Error('Failed to retrieve automated TAC recommendation from Gemini.');
      }

      const data = await res.json();
      setRcaReport(data.rcaReport || 'No recommendation returned.');
    } catch (err: any) {
      setRcaReport(`[TAC Engine Error] Failed to generate AI Root Cause Analysis: ${err.message}`);
    } finally {
      setIsAiAnalyzing(false);
    }
  };

  const handleUpdateRcaContext = (e: React.FormEvent) => {
    e.preventDefault();
    if (!analysisResult) return;
    triggerAiRca(analysisResult, customContext);
  };

  // Download filtered packets as a new PCAP file
  const handleDownloadFiltered = async () => {
    if (!analysisResult) return;
    try {
      const filteredIndices = filteredPackets.map(pkt => pkt.index);
      if (filteredIndices.length === 0) {
        alert('No packets match the active protocol/text filters to generate a download.');
        return;
      }

      const response = await fetch('/api/download-filtered', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          scenarioId: loadedScenario,
          pcapBase64: uploadedPcapBase64,
          filteredIndices
        })
      });

      if (!response.ok) {
        throw new Error('Server failed to construct filtered packet capture.');
      }

      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `autotac_filtered_${filteredIndices.length}_pkts.pcap`);
      document.body.appendChild(link);
      link.click();
      link.parentNode?.removeChild(link);
    } catch (err: any) {
      alert(`Error extracting filtered packet capture: ${err.message}`);
    }
  };

  // Convert Markdown structure into styled print-friendly HTML for enterprise PDF reports
  const renderMarkdownToHtml = (markdown: string): string => {
    if (!markdown) return '';
    const lines = markdown.split('\n');
    let inCodeBlock = false;
    let codeBlockContent: string[] = [];
    const htmlParts: string[] = [];

    lines.forEach(line => {
      if (line.trim().startsWith('```')) {
        if (inCodeBlock) {
          inCodeBlock = false;
          htmlParts.push(`<pre><code>${codeBlockContent.join('\n')}</code></pre>`);
          codeBlockContent = [];
        } else {
          inCodeBlock = true;
        }
        return;
      }

      if (inCodeBlock) {
        codeBlockContent.push(line);
        return;
      }

      if (line.startsWith('### ')) {
        htmlParts.push(`<h3>${parseInlineMarkdownToHtml(line.substring(4))}</h3>`);
      } else if (line.startsWith('## ')) {
        htmlParts.push(`<h2>${parseInlineMarkdownToHtml(line.substring(3))}</h2>`);
      } else if (line.startsWith('# ')) {
        htmlParts.push(`<h1>${parseInlineMarkdownToHtml(line.substring(2))}</h1>`);
      } else if (line.trim().startsWith('- ') || line.trim().startsWith('* ')) {
        htmlParts.push(`<li>${parseInlineMarkdownToHtml(line.trim().substring(2))}</li>`);
      } else if (line.trim() === '') {
        htmlParts.push('<br/>');
      } else {
        const orderedMatch = line.trim().match(/^(\d+)\.\s(.*)/);
        if (orderedMatch) {
          htmlParts.push(`<li style="list-style-type: decimal; margin-left: 20px;">${parseInlineMarkdownToHtml(orderedMatch[2])}</li>`);
        } else {
          htmlParts.push(`<p>${parseInlineMarkdownToHtml(line)}</p>`);
        }
      }
    });

    return htmlParts.join('\n');
  };

  const parseInlineMarkdownToHtml = (str: string): string => {
    let s = str.split('**').map((part, i) => i % 2 === 1 ? `<strong>${part}</strong>` : part).join('');
    s = s.split('`').map((part, i) => i % 2 === 1 ? `<code>${part}</code>` : part).join('');
    return s;
  };

  // Export current RCA report as a vector PDF via browser printing API
  const handleExportPdf = () => {
    if (!rcaReport) return;
    const printWindow = window.open('', '_blank');
    if (!printWindow) {
      alert('Please allow popups to export the PDF report.');
      return;
    }

    const scenarioTitle = 
      loadedScenario === 'congestion_retransmission' ? 'Hospital DB Loss Outage' :
      loadedScenario === 'dns_outage' ? 'DNS Server Failure Incident' :
      loadedScenario === 'plaintext_credentials' ? 'SOC Unencrypted Credentials Leak' :
      'Custom Capture Outage';

    printWindow.document.write(`
      <html>
        <head>
          <title>AutoTAC Incident RCA Report - ${scenarioTitle}</title>
          <style>
            @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700&display=swap');
            body {
              font-family: 'Plus Jakarta Sans', sans-serif;
              color: #0f172a;
              padding: 40px;
              line-height: 1.6;
              background-color: #ffffff;
            }
            .header-table {
              width: 100%;
              border-collapse: collapse;
              margin-bottom: 25px;
              border-bottom: 2px solid #06b6d4;
              padding-bottom: 15px;
            }
            .header-table td {
              padding: 6px 0;
              font-size: 11px;
              color: #475569;
            }
            .brand {
              font-weight: 800;
              color: #0f172a;
              font-size: 18px;
              letter-spacing: -0.02em;
            }
            .title-badge {
              text-align: right;
              font-weight: 700;
              color: #06b6d4;
              font-size: 11px;
              text-transform: uppercase;
              letter-spacing: 0.05em;
            }
            h1 {
              color: #0f172a;
              font-size: 22px;
              font-weight: 800;
              margin-top: 0;
              margin-bottom: 25px;
              letter-spacing: -0.025em;
            }
            h2 {
              color: #06b6d4;
              font-size: 15px;
              font-weight: 700;
              margin-top: 30px;
              margin-bottom: 12px;
              border-bottom: 1px solid #e2e8f0;
              padding-bottom: 6px;
            }
            h3 {
              color: #0f172a;
              font-size: 13px;
              font-weight: 600;
              margin-top: 20px;
              margin-bottom: 8px;
            }
            p, li {
              font-size: 12px;
              color: #334155;
              margin-bottom: 8px;
            }
            li {
              margin-bottom: 5px;
            }
            pre {
              background: #f8fafc;
              border: 1px solid #e2e8f0;
              padding: 12px 16px;
              border-radius: 6px;
              font-family: 'JetBrains Mono', monospace;
              font-size: 11px;
              overflow-x: auto;
              color: #0f172a;
              margin: 15px 0;
              line-height: 1.5;
            }
            code {
              background: #f1f5f9;
              padding: 2px 4px;
              border-radius: 4px;
              font-family: 'JetBrains Mono', monospace;
              font-size: 11px;
              color: #0f172a;
            }
            strong {
              color: #06b6d4;
              font-weight: 600;
            }
            .footer {
              margin-top: 60px;
              font-size: 10px;
              text-align: center;
              color: #94a3b8;
              border-top: 1px solid #e2e8f0;
              padding-top: 15px;
            }
            @media print {
              body {
                padding: 20px;
              }
              button {
                display: none;
              }
            }
          </style>
        </head>
        <body>
          <table class="header-table">
            <tr>
              <td class="brand">AutoTAC Incident Response</td>
              <td class="title-badge">Cisco/Palo Alto TAC Standards</td>
            </tr>
            <tr>
              <td>Incident Focus: <strong>${scenarioTitle}</strong></td>
              <td style="text-align: right;">Generated: ${new Date().toLocaleString()}</td>
            </tr>
            <tr>
              <td>Global Loss SLA: <strong>1.0% Threshold</strong></td>
              <td style="text-align: right;">Report Reference: autotac-rca-${Math.floor(100000 + Math.random() * 900000)}</td>
            </tr>
          </table>
          <h1>AUTOMATED TECHNICAL ROOT CAUSE ANALYSIS</h1>
          <div>${renderMarkdownToHtml(rcaReport)}</div>
          <div class="footer">
            AutoTAC network analytics and forensic reports are generated securely using deep packet inspection (DPI) summaries and L3 engineering playbooks.
          </div>
          <script>
            window.onload = function() {
              window.print();
              setTimeout(function() { window.close(); }, 500);
            }
          </script>
        </body>
      </html>
    `);
    printWindow.document.close();
  };

  const handleDownloadJsonReport = () => {
    if (!analysisResult) return;
    const jsonString = JSON.stringify({
      reportMetadata: {
        engine: "AutoTAC Automated PCAP RCA Engine",
        version: "1.0.0",
        scenario: loadedScenario,
        timestamp: new Date().toISOString(),
        threatLevel: analysisResult.globalRetransmissionRate > 1.0 ? 'CRITICAL' : 'NOMINAL'
      },
      analysisResult,
      aiReport: rcaReport
    }, null, 2);

    const blob = new Blob([jsonString], { type: 'application/json' });
    const url = window.URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', `autotac_analysis_report_${loadedScenario || 'custom'}.json`);
    document.body.appendChild(link);
    link.click();
    link.parentNode?.removeChild(link);
  };

  // Parse custom Markdown for AI display block (simple custom parser to support lists, headers, code, tables)
  const renderMarkdown = (text: string) => {
    if (!text) return null;
    const lines = text.split('\n');
    let inCodeBlock = false;
    let codeBlockContent: string[] = [];

    return lines.map((line, idx) => {
      // Handle code block
      if (line.trim().startsWith('```')) {
        if (inCodeBlock) {
          inCodeBlock = false;
          const content = codeBlockContent.join('\n');
          codeBlockContent = [];
          return (
            <pre key={idx} className="bg-slate-900 border border-slate-800 rounded-lg p-3 my-3 text-xs font-mono text-cyan-400 overflow-x-auto leading-relaxed">
              <code>{content}</code>
            </pre>
          );
        } else {
          inCodeBlock = true;
          return null;
        }
      }

      if (inCodeBlock) {
        codeBlockContent.push(line);
        return null;
      }

      // Headers
      if (line.startsWith('### ')) {
        return <h4 key={idx} className="text-sm font-semibold text-slate-100 mt-5 mb-2 flex items-center gap-1.5">{line.substring(4)}</h4>;
      }
      if (line.startsWith('## ')) {
        return <h3 key={idx} className="text-base font-bold text-cyan-400 mt-6 mb-3 border-b border-slate-800 pb-1.5">{line.substring(3)}</h3>;
      }
      if (line.startsWith('# ')) {
        return <h2 key={idx} className="text-lg font-extrabold text-white mt-7 mb-4">{line.substring(2)}</h2>;
      }

      // Unordered lists
      if (line.trim().startsWith('- ') || line.trim().startsWith('* ')) {
        return (
          <li key={idx} className="ml-5 list-disc text-slate-300 text-xs mb-1.5 leading-relaxed">
            {parseInlineStyles(line.trim().substring(2))}
          </li>
        );
      }

      // Ordered lists
      const orderedMatch = line.trim().match(/^(\d+)\.\s(.*)/);
      if (orderedMatch) {
        return (
          <li key={idx} className="ml-5 list-decimal text-slate-300 text-xs mb-1.5 leading-relaxed">
            {parseInlineStyles(orderedMatch[2])}
          </li>
        );
      }

      // Empty space
      if (line.trim() === '') {
        return <div key={idx} className="h-2"></div>;
      }

      // Default paragraph
      return (
        <p key={idx} className="text-xs text-slate-300 leading-relaxed mb-2">
          {parseInlineStyles(line)}
        </p>
      );
    });
  };

  const parseInlineStyles = (str: string) => {
    // Basic bold **text** replacement
    const parts = str.split('**');
    return parts.map((part, i) => {
      if (i % 2 === 1) {
        return <strong key={i} className="font-semibold text-cyan-300">{part}</strong>;
      }
      // Inline code `code` replacement
      const codeParts = part.split('`');
      return codeParts.map((subPart, j) => {
        if (j % 2 === 1) {
          return <code key={j} className="bg-slate-900 border border-slate-800 text-emerald-400 px-1 py-0.5 rounded font-mono text-xs">{subPart}</code>;
        }
        return subPart;
      });
    });
  };

  // Filter packet list based on interactive controls
  const filteredPackets = (analysisResult?.packets || []).filter((pkt) => {
    // Protocol filter
    if (protocolFilter !== 'ALL') {
      if (protocolFilter === 'RETRANSMISSION') {
        if (!pkt.isRetransmission) return false;
      } else if (protocolFilter === 'DUP_ACK') {
        if (!pkt.isDuplicateAck) return false;
      } else {
        if (pkt.protocol !== protocolFilter) return false;
      }
    }

    // Text search (search in IP, Ports, Info, payload)
    if (searchTerm) {
      const query = searchTerm.toLowerCase();
      const ipMatch = pkt.srcIp.toLowerCase().includes(query) || pkt.dstIp.toLowerCase().includes(query);
      const portMatch = pkt.srcPort?.toString().includes(query) || pkt.dstPort?.toString().includes(query);
      const infoMatch = pkt.info.toLowerCase().includes(query);
      const protoMatch = pkt.protocol.toLowerCase().includes(query);
      if (!ipMatch && !portMatch && !infoMatch && !protoMatch) return false;
    }

    // Advanced Logical Filter builder
    if (filterRules.length > 0) {
      if (!evaluateFilterRules(pkt)) return false;
    }

    return true;
  });

  return (
    <div className="min-h-screen flex flex-col bg-slate-950 text-slate-100 selection:bg-cyan-500 selection:text-slate-950">
      {/* SaaS Dashboard Layout - Header */}
      <header className="flex items-center justify-between px-6 py-4 border-b border-slate-900 bg-slate-950/80 backdrop-blur-md sticky top-0 z-30">
        {/* Brand Zone: Clean Title, no badges or comment syntax */}
        <div className="flex items-center gap-3">
          <Activity className="h-5 w-5 text-cyan-400" />
          <span className="text-base font-bold tracking-tight text-white font-sans">
            AutoTAC RCA Engine
          </span>
          <span className="text-slate-600">|</span>
          <div className="hidden sm:flex items-center gap-3 text-xs text-slate-500 font-medium">
            <span>Automated TAC Engineer Console</span>
            <span className="text-slate-700">·</span>
            <div className="flex items-center gap-1.5 bg-slate-900 px-2 py-1 rounded border border-slate-850">
              <span className={`w-1.5 h-1.5 rounded-full inline-block ${backendStatus.online ? 'bg-emerald-500 animate-pulse' : 'bg-red-500'}`}></span>
              <span className="text-[10px] font-mono text-slate-400">
                {backendStatus.online ? `Engine: Online (Uptime: ${backendStatus.uptime}s)` : 'Engine: Offline'}
              </span>
            </div>
            <button
              onClick={handleReTriggerAnalysis}
              disabled={isParsing || isAiAnalyzing || !backendStatus.online}
              className="flex items-center gap-1 px-2 py-1 bg-slate-900 hover:bg-slate-850 border border-slate-800 text-cyan-400 hover:text-cyan-300 rounded text-[10px] transition-all disabled:opacity-50 cursor-pointer"
              title="Re-run background analysis engine task"
            >
              <RefreshCw className={`h-3 w-3 ${isParsing || isAiAnalyzing ? 'animate-spin' : ''}`} />
              <span>Re-trigger Analysis</span>
            </button>
          </div>
        </div>

        {/* Top bar contract actions & upload */}
        <div className="flex items-center gap-4">
          <label className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-slate-900 hover:bg-slate-850 text-slate-300 border border-slate-800 hover:border-slate-700 rounded-md cursor-pointer transition-all duration-150 whitespace-nowrap">
            <Upload className="h-3.5 w-3.5 text-cyan-400" />
            <span>Upload Capture (.pcap)</span>
            <input
              type="file"
              accept=".pcap,.pcapng"
              multiple
              className="hidden"
              onChange={handleFileUpload}
            />
          </label>
        </div>
      </header>

      {/* Global Alerts Ticker */}
      <GlobalAlertsTicker analysisResult={analysisResult} />

      {/* Main Sandbox Area & Sub Header */}
      <div className="bg-slate-900/40 border-b border-slate-900 px-6 py-3 flex flex-wrap gap-4 items-center justify-between">
        <div className="flex items-center gap-2 text-xs text-slate-500">
          <span>Active Session</span>
          <span>/</span>
          <span className="text-slate-300 font-medium">
            {loadedScenario === 'congestion_retransmission' && 'SEV-1 Hospital DB Packet Drops'}
            {loadedScenario === 'dns_outage' && 'SEV-1 Local DNS Server Failure'}
            {loadedScenario === 'plaintext_credentials' && 'SEV-2 Cleartext Credential Incident'}
            {loadedScenario === 'voip_telephony' && 'SEV-1 Telephony Degradation & SIP Failure'}
            {!loadedScenario && (analysisResult ? 'Custom File Upload' : 'No Active Session')}
          </span>
        </div>

        {/* Scenario Sandbox Picker */}
        <div className="flex items-center gap-2">
          <span className="text-xs text-slate-400 font-medium whitespace-nowrap">Load Outage Presets:</span>
          <div className="flex flex-wrap gap-1">
            <button
              onClick={() => handleLoadScenario('congestion_retransmission')}
              className={`px-2.5 py-1 text-xs rounded transition-colors ${
                loadedScenario === 'congestion_retransmission'
                  ? 'bg-cyan-500/10 text-cyan-300 border border-cyan-500/30'
                  : 'bg-slate-900 hover:bg-slate-850 text-slate-400 border border-slate-800'
              }`}
            >
              Hospital DB Drops (TCP Loss)
            </button>
            <button
              onClick={() => handleLoadScenario('dns_outage')}
              className={`px-2.5 py-1 text-xs rounded transition-colors ${
                loadedScenario === 'dns_outage'
                  ? 'bg-cyan-500/10 text-cyan-300 border border-cyan-500/30'
                  : 'bg-slate-900 hover:bg-slate-850 text-slate-400 border border-slate-800'
              }`}
            >
              DNS Daemon Crash
            </button>
            <button
              onClick={() => handleLoadScenario('plaintext_credentials')}
              className={`px-2.5 py-1 text-xs rounded transition-colors ${
                loadedScenario === 'plaintext_credentials'
                  ? 'bg-cyan-500/10 text-cyan-300 border border-cyan-500/30'
                  : 'bg-slate-900 hover:bg-slate-850 text-slate-400 border border-slate-800'
              }`}
            >
              Credentials Leak
            </button>
            <button
              onClick={() => handleLoadScenario('voip_telephony')}
              className={`px-2.5 py-1 text-xs rounded transition-colors ${
                loadedScenario === 'voip_telephony'
                  ? 'bg-cyan-500/10 text-cyan-300 border border-cyan-500/30'
                  : 'bg-slate-900 hover:bg-slate-850 text-slate-400 border border-slate-800'
              }`}
            >
              VoIP SIP/RTP Jitter
            </button>
          </div>
        </div>
      </div>

      <div className="flex-1 flex flex-col lg:flex-row">
        {/* Sidebar Navigation */}
        <aside className="w-full lg:w-64 border-r border-slate-900 p-4 shrink-0 flex flex-col gap-5 bg-slate-950/40">
          <div className="flex flex-col gap-1">
            <span className="text-slate-500 text-[10px] font-bold tracking-wider uppercase px-2 mb-1">
              Inspection Panels
            </span>
            <button
              onClick={() => setActiveTab('dashboard')}
              className={`w-full flex items-center justify-between px-3 py-2 text-xs font-medium rounded-md transition-colors ${
                activeTab === 'dashboard'
                  ? 'bg-slate-900 text-cyan-400'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/30'
              }`}
            >
              <div className="flex items-center gap-2">
                <Database className="h-4 w-4" />
                <span>RCA Dashboard</span>
              </div>
              <ChevronRight className="h-3 w-3" />
            </button>

            <button
              onClick={() => setActiveTab('packets')}
              className={`w-full flex items-center justify-between px-3 py-2 text-xs font-medium rounded-md transition-colors ${
                activeTab === 'packets'
                  ? 'bg-slate-900 text-cyan-400'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/30'
              }`}
            >
              <div className="flex items-center gap-2">
                <Terminal className="h-4 w-4" />
                <span>Wireshark Stream</span>
              </div>
              <span className="text-[10px] font-mono font-medium text-slate-500 bg-slate-900 px-1.5 py-0.5 rounded">
                {analysisResult?.totalPackets || 0}
              </span>
            </button>

            <button
              onClick={() => setActiveTab('dns')}
              className={`w-full flex items-center justify-between px-3 py-2 text-xs font-medium rounded-md transition-colors ${
                activeTab === 'dns'
                  ? 'bg-slate-900 text-cyan-400'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/30'
              }`}
            >
              <div className="flex items-center gap-2">
                <Globe className="h-4 w-4" />
                <span>DNS Health Logs</span>
              </div>
              {analysisResult && analysisResult.dnsFailureCount > 0 && (
                <span className="text-[10px] font-mono font-medium text-amber-400 bg-amber-500/10 px-1.5 py-0.5 rounded border border-amber-500/25">
                  {analysisResult.dnsFailureCount}
                </span>
              )}
            </button>

            <button
              onClick={() => setActiveTab('security')}
              className={`w-full flex items-center justify-between px-3 py-2 text-xs font-medium rounded-md transition-colors ${
                activeTab === 'security'
                  ? 'bg-slate-900 text-cyan-400'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/30'
              }`}
            >
              <div className="flex items-center gap-2">
                <ShieldAlert className="h-4 w-4" />
                <span>SOC Security Vault</span>
              </div>
              {analysisResult && analysisResult.plaintextCredentialsCount > 0 && (
                <span className="text-[10px] font-mono font-medium text-red-400 bg-red-500/10 px-1.5 py-0.5 rounded border border-red-500/25 animate-pulse">
                  {analysisResult.plaintextCredentialsCount}
                </span>
              )}
            </button>

            <button
              onClick={() => setActiveTab('batch')}
              className={`w-full flex items-center justify-between px-3 py-2 text-xs font-medium rounded-md transition-colors ${
                activeTab === 'batch'
                  ? 'bg-slate-900 text-cyan-400'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/30'
              }`}
            >
              <div className="flex items-center gap-2">
                <Sliders className="h-4 w-4" />
                <span>Compare Captures (Batch)</span>
              </div>
              {batchResults.length > 0 && (
                <span className="text-[10px] font-mono font-medium text-cyan-400 bg-cyan-500/10 px-1.5 py-0.5 rounded border border-cyan-500/25">
                  {batchResults.length}
                </span>
              )}
            </button>

            <button
              onClick={() => setActiveTab('topology')}
              className={`w-full flex items-center justify-between px-3 py-2 text-xs font-medium rounded-md transition-colors ${
                activeTab === 'topology'
                  ? 'bg-slate-900 text-cyan-400'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/30'
              }`}
            >
              <div className="flex items-center gap-2">
                <Globe className="h-4 w-4 text-cyan-500/70" />
                <span>Network Topology</span>
              </div>
              <span className="text-[10px] font-mono font-medium text-cyan-400 bg-cyan-500/10 px-1.5 py-0.5 rounded border border-cyan-500/25">
                Live
              </span>
            </button>

            <button
              onClick={() => setActiveTab('latency')}
              className={`w-full flex items-center justify-between px-3 py-2 text-xs font-medium rounded-md transition-colors ${
                activeTab === 'latency'
                  ? 'bg-slate-900 text-cyan-400'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/30'
              }`}
            >
              <div className="flex items-center gap-2">
                <Cpu className="h-4 w-4" />
                <span>Latency Arbiter</span>
              </div>
              <span className="text-[10px] font-mono font-medium text-cyan-400 bg-cyan-500/10 px-1.5 py-0.5 rounded border border-cyan-500/25">
                New
              </span>
            </button>

            <button
              onClick={() => setActiveTab('middlebox')}
              className={`w-full flex items-center justify-between px-3 py-2 text-xs font-medium rounded-md transition-colors ${
                activeTab === 'middlebox'
                  ? 'bg-slate-900 text-cyan-400'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/30'
              }`}
            >
              <div className="flex items-center gap-2">
                <ShieldAlert className="h-4 w-4 text-red-500/80" />
                <span>RST Fingerprinter</span>
              </div>
              <span className="text-[10px] font-mono font-medium text-red-400 bg-red-500/10 px-1.5 py-0.5 rounded border border-red-500/25">
                Sec
              </span>
            </button>

            <button
              onClick={() => setActiveTab('tls')}
              className={`w-full flex items-center justify-between px-3 py-2 text-xs font-medium rounded-md transition-colors ${
                activeTab === 'tls'
                  ? 'bg-slate-900 text-cyan-400'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/30'
              }`}
            >
              <div className="flex items-center gap-2">
                <Key className="h-4 w-4 text-purple-400/80" />
                <span>TLS Handshake Health</span>
              </div>
              {analysisResult && (analysisResult.tlsAlerts || []).length > 0 && (
                <span className="text-[10px] font-mono font-medium text-purple-400 bg-purple-500/10 px-1.5 py-0.5 rounded border border-purple-500/25 animate-pulse">
                  {(analysisResult.tlsAlerts || []).length}
                </span>
              )}
            </button>

            <button
              onClick={() => setActiveTab('correlation')}
              className={`w-full flex items-center justify-between px-3 py-2 text-xs font-medium rounded-md transition-colors ${
                activeTab === 'correlation'
                  ? 'bg-slate-900 text-cyan-400'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/30'
              }`}
            >
              <div className="flex items-center gap-2">
                <Sliders className="h-4 w-4 text-red-400 animate-pulse" />
                <span>Ingress/Egress Correlation</span>
              </div>
              <span className="text-[10px] font-mono font-medium text-red-400 bg-red-500/10 px-1.5 py-0.5 rounded border border-red-500/25">
                DropProof
              </span>
            </button>

            <button
              onClick={() => setActiveTab('asymmetric')}
              className={`w-full flex items-center justify-between px-3 py-2 text-xs font-medium rounded-md transition-colors ${
                activeTab === 'asymmetric'
                  ? 'bg-slate-900 text-cyan-400'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/30'
              }`}
            >
              <div className="flex items-center gap-2">
                <AlertTriangle className="h-4 w-4 text-amber-500 animate-pulse" />
                <span>Asymmetric Routing</span>
              </div>
              {analysisResult && (analysisResult.asymmetricRouteAnomalies || []).length > 0 && (
                <span className="text-[10px] font-mono font-medium text-amber-400 bg-amber-500/10 px-1.5 py-0.5 rounded border border-amber-500/25">
                  {(analysisResult.asymmetricRouteAnomalies || []).length}
                </span>
              )}
            </button>

            <button
              onClick={() => setActiveTab('microburst')}
              className={`w-full flex items-center justify-between px-3 py-2 text-xs font-medium rounded-md transition-colors ${
                activeTab === 'microburst'
                  ? 'bg-slate-900 text-cyan-400'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/30'
              }`}
            >
              <div className="flex items-center gap-2">
                <Activity className="h-4 w-4 text-orange-400 animate-pulse" />
                <span>Microburst Visualizer</span>
              </div>
              <span className="text-[10px] font-mono font-medium text-orange-400 bg-orange-500/10 px-1.5 py-0.5 rounded border border-orange-500/25">
                1ms
              </span>
            </button>

            <button
              onClick={() => setActiveTab('shadow_iot')}
              className={`w-full flex items-center justify-between px-3 py-2 text-xs font-medium rounded-md transition-colors ${
                activeTab === 'shadow_iot'
                  ? 'bg-slate-900 text-cyan-400'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/30'
              }`}
            >
              <div className="flex items-center gap-2">
                <Cpu className="h-4 w-4 text-purple-400 animate-pulse" />
                <span>Shadow IoT & Fingerprint</span>
              </div>
              {analysisResult && (analysisResult.fingerprintedDevices || []).filter(d => d.isRogue).length > 0 && (
                <span className="text-[10px] font-mono font-medium text-red-400 bg-red-500/10 px-1.5 py-0.5 rounded border border-red-500/25 animate-pulse">
                  {(analysisResult.fingerprintedDevices || []).filter(d => d.isRogue).length} Alert
                </span>
              )}
            </button>

            <button
              onClick={() => setActiveTab('radius')}
              className={`w-full flex items-center justify-between px-3 py-2 text-xs font-medium rounded-md transition-colors ${
                activeTab === 'radius'
                  ? 'bg-slate-900 text-cyan-400'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/30'
              }`}
            >
              <div className="flex items-center gap-2">
                <Key className="h-4 w-4 text-yellow-400 animate-pulse" />
                <span>Identity & RADIUS Logs</span>
              </div>
              {analysisResult && (analysisResult.radiusRejects || []).length > 0 && (
                <span className="text-[10px] font-mono font-medium text-yellow-400 bg-yellow-500/10 px-1.5 py-0.5 rounded border border-yellow-500/25 animate-pulse">
                  {(analysisResult.radiusRejects || []).length} Rejects
                </span>
              )}
            </button>

            <button
              onClick={() => setActiveTab('overlay')}
              className={`w-full flex items-center justify-between px-3 py-2 text-xs font-medium rounded-md transition-colors ${
                activeTab === 'overlay'
                  ? 'bg-slate-900 text-cyan-400'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/30'
              }`}
            >
              <div className="flex items-center gap-2">
                <Cloud className="h-4 w-4 text-indigo-400 animate-pulse" />
                <span>Cloud Overlay Forensics</span>
              </div>
              {analysisResult && (analysisResult.packets || []).filter(p => p.overlayData).length > 0 && (
                <span className="text-[10px] font-mono font-medium text-indigo-400 bg-indigo-500/10 px-1.5 py-0.5 rounded border border-indigo-500/25 animate-pulse">
                  {(analysisResult.packets || []).filter(p => p.overlayData).length} Tunnels
                </span>
              )}
            </button>

            <button
              onClick={() => setActiveTab('routing')}
              className={`w-full flex items-center justify-between px-3 py-2 text-xs font-medium rounded-md transition-colors ${
                activeTab === 'routing'
                  ? 'bg-slate-900 text-cyan-400'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/30'
              }`}
            >
              <div className="flex items-center gap-2">
                <GitMerge className="h-4 w-4 text-emerald-400 animate-pulse" />
                <span>BGP & OSPF Diagnostics</span>
              </div>
              {analysisResult && ((analysisResult.bgpNotifications || []).length + (analysisResult.ospfMismatches || []).length) > 0 && (
                <span className="text-[10px] font-mono font-medium text-emerald-400 bg-emerald-500/10 px-1.5 py-0.5 rounded border border-emerald-500/25 animate-pulse">
                  {(analysisResult.bgpNotifications || []).length + (analysisResult.ospfMismatches || []).length} Outages
                </span>
              )}
            </button>

            <button
              onClick={() => setActiveTab('voip')}
              className={`w-full flex items-center justify-between px-3 py-2 text-xs font-medium rounded-md transition-colors ${
                activeTab === 'voip'
                  ? 'bg-slate-900 text-cyan-400'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/30'
              }`}
            >
              <div className="flex items-center gap-2">
                <PhoneCall className="h-4 w-4 text-violet-400 animate-pulse" />
                <span>Voice & Telephony Health</span>
              </div>
              {analysisResult?.voipAnalysis && (analysisResult.voipAnalysis.totalCalls > 0 || analysisResult.voipAnalysis.rtpStreams.length > 0) && (
                <span className={`text-[10px] font-mono font-medium px-1.5 py-0.5 rounded border ${
                  analysisResult.voipAnalysis.hasSevereDegradation
                    ? 'text-amber-400 bg-amber-500/10 border-amber-500/25 animate-pulse'
                    : 'text-emerald-400 bg-emerald-500/10 border-emerald-500/25'
                }`}>
                  {analysisResult.voipAnalysis.maxRtpPacketLossPercent >= 3.0
                    ? `${analysisResult.voipAnalysis.maxRtpPacketLossPercent}% Loss`
                    : analysisResult.voipAnalysis.failedCallsCount > 0
                    ? `${analysisResult.voipAnalysis.failedCallsCount} SIP Errs`
                    : `${analysisResult.voipAnalysis.totalCalls} Calls`}
                </span>
              )}
            </button>
          </div>

          <div className="border-t border-slate-900 pt-4 flex flex-col gap-3">
            <span className="text-slate-500 text-[10px] font-bold tracking-wider uppercase px-2">
              Physical File Validation
            </span>

            {loadedScenario ? (
              <div className="bg-slate-900/40 border border-slate-900 p-3 rounded-lg flex flex-col gap-2">
                <p className="text-[11px] text-slate-400 leading-relaxed">
                  You are looking at parsed results. Want to inspect this capture in your local desktop Wireshark?
                </p>
                <a
                  href={`/api/download-scenario/${loadedScenario}`}
                  className="flex items-center justify-center gap-1.5 py-1.5 px-2.5 bg-slate-900 hover:bg-slate-850 border border-slate-850 hover:border-slate-750 text-slate-300 font-medium rounded text-[11px] transition-colors"
                >
                  <Download className="h-3.5 w-3.5 text-cyan-400" />
                  <span>Download Real .PCAP</span>
                </a>
              </div>
            ) : (
              <p className="text-[11px] text-slate-500 italic px-2 leading-relaxed">
                Upload a capture file to enable the local physical download option.
              </p>
            )}
          </div>

          <div className="mt-auto border-t border-slate-900 pt-4 flex flex-col gap-2">
            <div className="flex items-center justify-between px-2 text-slate-500 text-[10px]">
              <div className="flex items-center gap-1.5">
                <Cpu className="h-3.5 w-3.5 text-slate-400" />
                <span className="tracking-tight">AutoTAC Engine</span>
              </div>
              <span className={`px-1.5 py-0.5 rounded text-[8px] font-bold uppercase tracking-wider ${backendStatus.online ? 'bg-emerald-500/10 border border-emerald-500/25 text-emerald-400 animate-pulse' : 'bg-red-500/10 border border-red-500/25 text-red-400'}`}>
                {backendStatus.online ? 'Online' : 'Offline'}
              </span>
            </div>
            {backendStatus.online && (
              <div className="px-2 font-mono text-[9px] text-slate-500 flex flex-col gap-0.5 tabular-nums">
                <div className="flex justify-between">
                  <span>Engine Uptime:</span>
                  <span className="text-slate-400 font-semibold">{backendStatus.uptime}s</span>
                </div>
                <div className="flex justify-between">
                  <span>Memory Allocation:</span>
                  <span className="text-slate-400 font-semibold">{backendStatus.memoryUsage} MB</span>
                </div>
              </div>
            )}
          </div>
        </aside>

        {/* Content Viewport */}
        <main className="flex-1 p-6 flex flex-col gap-6 overflow-y-auto max-w-[1600px] w-full">
          {isParsing && (
            <div className="flex flex-col items-center justify-center py-16 gap-3 bg-slate-900/20 border border-slate-950 rounded-xl">
              <RefreshCw className="h-8 w-8 text-cyan-400 animate-spin" />
              <div className="text-center">
                <p className="text-xs text-slate-300 font-semibold">Parsing Network Capture Binary...</p>
                <p className="text-[11px] text-slate-500">Deconstructing network frame structures, TCP headers, and scanning payloads.</p>
              </div>
            </div>
          )}

          {errorMsg && (
            <div className="p-4 bg-red-950/20 border border-red-500/20 rounded-xl flex gap-3 items-start">
              <AlertTriangle className="h-5 w-5 text-red-500 shrink-0 mt-0.5" />
              <div>
                <h4 className="text-xs font-semibold text-red-400">Analysis Parser Error</h4>
                <p className="text-[11px] text-slate-400 leading-relaxed mt-1">{errorMsg}</p>
              </div>
            </div>
          )}

          {analysisResult && !isParsing && (
            <>
              {/* TAB 1: RCA DASHBOARD */}
              {activeTab === 'dashboard' && (
                <div className="flex flex-col gap-6">
                  {/* Top Row: Metric Dashboard Displays */}
                  <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
                    <div className="bg-slate-900/30 border border-slate-900 p-4 rounded-xl flex flex-col gap-1.5 relative overflow-hidden">
                      <span className="text-[11px] text-slate-500 font-medium">Global Packet Count</span>
                      <span className="text-2xl font-bold font-mono tracking-tight text-slate-100 tabular-nums">
                        {analysisResult.totalPackets}
                      </span>
                      <div className="flex items-center gap-2 text-[10px] text-slate-500 mt-1">
                        <span>Total Bytes</span>
                        <span>·</span>
                        <span className="font-mono tabular-nums">{analysisResult.totalBytes.toLocaleString()} B</span>
                      </div>
                    </div>

                    <div className="bg-slate-900/30 border border-slate-900 p-4 rounded-xl flex flex-col gap-1.5 relative overflow-hidden">
                      <span className="text-[11px] text-slate-500 font-medium">TCP Retransmission Rate</span>
                      <span className={`text-2xl font-bold font-mono tracking-tight tabular-nums ${
                        analysisResult.globalRetransmissionRate > 1.0 ? 'text-red-400' : 'text-emerald-400'
                      }`}>
                        {analysisResult.globalRetransmissionRate.toFixed(2)}%
                      </span>
                      <div className="flex items-center gap-2 text-[10px] text-slate-500 mt-1">
                        <span>SLA Threshold</span>
                        <span>·</span>
                        <span className="text-slate-400 font-mono">&lt; 1.00%</span>
                      </div>
                    </div>

                    <div className="bg-slate-900/30 border border-slate-900 p-4 rounded-xl flex flex-col gap-1.5 relative overflow-hidden">
                      <span className="text-[11px] text-slate-500 font-medium">Packet Drops Identified</span>
                      <span className="text-2xl font-bold font-mono tracking-tight text-slate-100 tabular-nums">
                        {analysisResult.retransmissionCount}
                      </span>
                      <div className="flex items-center gap-2 text-[10px] text-slate-500 mt-1">
                        <span>Dup ACKs Detected</span>
                        <span>·</span>
                        <span className="font-mono tabular-nums">{analysisResult.duplicateAckCount}</span>
                      </div>
                    </div>

                    <div className="bg-slate-900/30 border border-slate-900 p-4 rounded-xl flex flex-col gap-1.5 relative overflow-hidden">
                      <span className="text-[11px] text-slate-500 font-medium">Avg RTT Latency</span>
                      <span className={`text-2xl font-bold font-mono tracking-tight tabular-nums ${
                        (analysisResult.averageRtt || 0) > 150 ? 'text-amber-400' : 'text-slate-100'
                      }`}>
                        {analysisResult.averageRtt ? `${analysisResult.averageRtt.toFixed(1)} ms` : '0.0 ms'}
                      </span>
                      <div className="flex items-center gap-2 text-[10px] text-slate-500 mt-1">
                        <span>Max Observed</span>
                        <span>·</span>
                        <span className="font-mono tabular-nums">{analysisResult.maxRtt ? `${analysisResult.maxRtt.toFixed(1)} ms` : '0.0 ms'}</span>
                      </div>
                    </div>

                    <div className="bg-slate-900/30 border border-slate-900 p-4 rounded-xl flex flex-col gap-1.5 relative overflow-hidden">
                      <span className="text-[11px] text-slate-500 font-medium">Anomalies Detected</span>
                      <span className={`text-2xl font-bold font-mono tracking-tight tabular-nums ${
                        (analysisResult.dnsFailureCount > 0 || analysisResult.plaintextCredentialsCount > 0)
                          ? 'text-amber-400 animate-pulse'
                          : 'text-emerald-400'
                      }`}>
                        {analysisResult.dnsFailureCount + analysisResult.plaintextCredentialsCount}
                      </span>
                      <div className="flex items-center gap-1.5 text-[10px] text-slate-500 mt-1">
                        <span className="text-red-400">{analysisResult.plaintextCredentialsCount} Credentials</span>
                        <span>·</span>
                        <span className="text-amber-400">{analysisResult.dnsFailureCount} DNS Failures</span>
                      </div>
                    </div>
                  </div>

                  {/* TTL Path Flapping & Spoofing Alerts Panel */}
                  {analysisResult.ttlAnomalies && analysisResult.ttlAnomalies.length > 0 && (
                    <div className="bg-amber-500/5 border border-amber-500/20 rounded-xl p-4 flex flex-col gap-3">
                      <div className="flex items-center gap-2 text-xs font-semibold text-amber-400">
                        <AlertTriangle className="h-4 w-4 animate-pulse" />
                        <span>Layer-3 TTL Path Flapping & Spoofing Diagnostics</span>
                      </div>
                      <div className="flex flex-col gap-2">
                        {analysisResult.ttlAnomalies.map((anomaly, idx) => {
                          let badgeBg = 'bg-amber-500/10 border-amber-500/20 text-amber-400';
                          if (anomaly.type === 'Possible IP Spoofing') {
                            badgeBg = 'bg-red-500/10 border-red-500/20 text-red-400 animate-pulse';
                          } else if (anomaly.type === 'Routing Loop') {
                            badgeBg = 'bg-yellow-500/10 border-yellow-500/20 text-yellow-400';
                          }

                          return (
                            <div key={idx} className="flex flex-col md:flex-row md:items-center justify-between gap-3 bg-slate-950 p-3 rounded-lg border border-slate-900 text-xs">
                              <div className="flex flex-col gap-1">
                                <div className="flex items-center gap-2 flex-wrap">
                                  <span className="font-mono text-[11px] text-slate-200 font-bold">{anomaly.ip}</span>
                                  <span className={`px-1.5 py-0.5 text-[8px] font-sans font-semibold rounded border ${badgeBg} uppercase tracking-wider`}>
                                    {anomaly.type}
                                  </span>
                                </div>
                                <p className="text-[11px] text-slate-400 leading-relaxed mt-1">
                                  {anomaly.description}
                                </p>
                              </div>
                              <div className="flex items-center gap-4 shrink-0 text-[10px] text-slate-500 font-mono">
                                <div>
                                  <span className="text-slate-400">Observed TTLs:</span> <span className="text-cyan-400 font-bold">{anomaly.ttls.join(', ')}</span>
                                </div>
                                <div className="hidden sm:block">
                                  <span className="text-slate-400">Packets checked:</span> <span className="text-slate-300 font-bold">{anomaly.packetCount}</span>
                                </div>
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  )}

                  {/* Automated Capture Profiler Panel */}
                  {analysisResult.captureProfiler && (
                    <div className="bg-slate-900/20 border border-slate-900 rounded-xl p-5 flex flex-col gap-4">
                      <div className="flex items-center justify-between border-b border-slate-900 pb-3">
                        <div className="flex items-center gap-2">
                          <Sliders className="h-4 w-4 text-cyan-400" />
                          <span className="text-xs font-semibold text-slate-200">
                            Automated Capture Profiler & MTU Analyzer
                          </span>
                        </div>
                        <span className="text-[10px] font-mono text-slate-500 uppercase tracking-widest font-semibold">
                          Deep Packet Sizing & Window Statistics
                        </span>
                      </div>

                      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                        {/* 1. Protocol Breakdown & Bytes Volume */}
                        <div className="bg-slate-950 p-4 rounded-lg border border-slate-900 flex flex-col gap-3">
                          <span className="text-[11px] text-slate-400 font-bold uppercase tracking-wider">
                            Protocol Byte & Count Allocation
                          </span>
                          <div className="flex flex-col gap-2.5 max-h-[160px] overflow-y-auto pr-1">
                            {analysisResult.captureProfiler.protocolBreakdown
                              .filter(p => p.count > 0)
                              .map((p) => (
                                <div key={p.protocol} className="flex flex-col gap-1">
                                  <div className="flex items-center justify-between text-[11px] font-mono">
                                    <span className="text-cyan-400 font-semibold">{p.protocol}</span>
                                    <span className="text-slate-400 font-medium">{p.percentage.toFixed(1)}%</span>
                                  </div>
                                  <div className="flex justify-between text-[10px] text-slate-500 font-mono">
                                    <span>{p.count.toLocaleString()} pkts</span>
                                    <span>{p.bytes.toLocaleString()} B</span>
                                  </div>
                                  <div className="w-full h-1 bg-slate-900 rounded-full overflow-hidden">
                                    <div className="h-full bg-cyan-500/80" style={{ width: `${p.percentage}%` }}></div>
                                  </div>
                                </div>
                              ))}
                          </div>
                        </div>

                        {/* 2. TCP Window size distributions */}
                        <div className="bg-slate-950 p-4 rounded-lg border border-slate-900 flex flex-col gap-3">
                          <span className="text-[11px] text-slate-400 font-bold uppercase tracking-wider">
                            Common TCP Window Sizes (Congestion Profile)
                          </span>
                          <div className="flex flex-col gap-2 max-h-[160px] overflow-y-auto pr-1">
                            {analysisResult.captureProfiler.commonTcpWindowSizes.map((w, idx) => (
                              <div key={idx} className="flex items-center justify-between text-xs font-mono py-1 border-b border-slate-900/40 last:border-b-0">
                                <div className="flex items-center gap-1.5">
                                  <span className="text-slate-500">#{idx + 1}</span>
                                  <span className="text-slate-300 font-semibold tabular-nums">{w.windowSize.toLocaleString()} B</span>
                                </div>
                                <div className="text-[10px] text-slate-500 tabular-nums">
                                  <span>{w.count} pkts ({w.percentage.toFixed(1)}%)</span>
                                </div>
                              </div>
                            ))}
                            {analysisResult.captureProfiler.commonTcpWindowSizes.length === 0 && (
                              <div className="text-center py-6 text-slate-500 italic text-xs">No active TCP window packets parsed.</div>
                            )}
                          </div>
                        </div>

                        {/* 3. MTU & Size analysis */}
                        <div className="bg-slate-950 p-4 rounded-lg border border-slate-900 flex flex-col gap-3 justify-between">
                          <div className="flex flex-col gap-2">
                            <span className="text-[11px] text-slate-400 font-bold uppercase tracking-wider block">
                              Path MTU & Frame Sizing Diagnostics
                            </span>
                            <div className="flex items-baseline gap-2 mt-1">
                              <span className="text-slate-500 text-[10px] font-mono">Max Frame:</span>
                              <span className="text-lg font-bold font-mono text-slate-100 tabular-nums">
                                {analysisResult.captureProfiler.mtuAnalysis.maxFrameSize} B
                              </span>
                              <span className="text-slate-500 text-[10px] font-mono ml-4">Avg Frame:</span>
                              <span className="text-lg font-bold font-mono text-slate-100 tabular-nums">
                                {Math.round(analysisResult.captureProfiler.averageFrameSize)} B
                              </span>
                            </div>
                            <p className="text-[11px] text-slate-400 leading-relaxed mt-1">
                              {analysisResult.captureProfiler.mtuAnalysis.description}
                            </p>
                          </div>
                          
                          {analysisResult.captureProfiler.mtuAnalysis.possibleMtuIssue && (
                            <div className="bg-red-500/10 border border-red-500/25 px-2.5 py-1.5 rounded flex items-center gap-1.5 text-[10px] text-red-400 font-semibold font-sans mt-2 animate-pulse uppercase tracking-wider">
                              <AlertTriangle className="h-3.5 w-3.5" />
                              <span>Possible MTU Bottleneck detected</span>
                            </div>
                          )}
                        </div>
                      </div>
                    </div>
                  )}

                  {/* Split Screen: AI Root Cause Analysis and Culprit Flows */}
                  <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
                    {/* Left Column: AI RCA and TAC Intelligence */}
                    <div className="flex flex-col gap-6">
                      {/* Left Column Card 1: Automated AI Root Cause Statement */}
                      <div className="bg-slate-900/20 border border-slate-900 rounded-xl p-5 flex flex-col gap-4 relative">
                        <div className="flex items-center justify-between border-b border-slate-900 pb-3">
                          <div className="flex items-center gap-2">
                            <Cpu className="h-4 w-4 text-cyan-400" />
                            <span className="text-xs font-semibold text-slate-200">
                              Automated TAC AI Root Cause Analysis
                            </span>
                          </div>
                          <div className="flex items-center gap-1.5 text-[10px] text-slate-500">
                            <span>Model</span>
                            <span>·</span>
                            <span className="text-slate-400 font-mono">gemini-3.8-flash</span>
                          </div>
                        </div>

                        {/* Steering Context Form */}
                        <form onSubmit={handleUpdateRcaContext} className="flex gap-2">
                          <input
                            type="text"
                            placeholder="Add diagnostic notes (e.g. 'We suspect asymmetric routing on firewall')"
                            value={customContext}
                            onChange={(e) => setCustomContext(e.target.value)}
                            className="flex-1 bg-slate-950 border border-slate-850 hover:border-slate-800 text-xs text-slate-300 rounded px-2.5 py-1.5 focus:outline-none focus:border-cyan-500 transition-colors"
                          />
                          <button
                            type="submit"
                            disabled={isAiAnalyzing}
                            className="px-3 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold rounded text-xs transition-colors shrink-0 flex items-center gap-1 disabled:opacity-50"
                          >
                            <RefreshCw className={`h-3 w-3 ${isAiAnalyzing ? 'animate-spin' : ''}`} />
                            <span>Analyse</span>
                          </button>
                          {analysisResult && (
                            <button
                              type="button"
                              onClick={handleDownloadJsonReport}
                              className="px-3 py-1.5 bg-slate-900 hover:bg-slate-850 text-emerald-400 font-semibold border border-slate-800 hover:border-slate-750 rounded text-xs transition-colors shrink-0 flex items-center gap-1"
                              title="Download full analysis state as JSON"
                            >
                              <FileText className="h-3.5 w-3.5 text-emerald-400" />
                              <span>Download Report</span>
                            </button>
                          )}
                          {rcaReport && !isAiAnalyzing && (
                            <button
                              type="button"
                              onClick={handleExportPdf}
                              className="px-3 py-1.5 bg-slate-900 hover:bg-slate-850 text-cyan-400 font-semibold border border-slate-800 hover:border-slate-750 rounded text-xs transition-colors shrink-0 flex items-center gap-1"
                              title="Export Incident Report to PDF"
                            >
                              <Download className="h-3.5 w-3.5" />
                              <span>Export PDF</span>
                            </button>
                          )}
                        </form>

                        {isAiAnalyzing ? (
                          <div className="flex flex-col gap-3 py-6">
                            <div className="h-3 w-3/4 bg-slate-850 animate-pulse rounded"></div>
                            <div className="h-3 w-5/6 bg-slate-850 animate-pulse rounded"></div>
                            <div className="h-3 w-1/2 bg-slate-850 animate-pulse rounded"></div>
                            <div className="h-3 w-2/3 bg-slate-850 animate-pulse rounded"></div>
                          </div>
                        ) : (
                          <div className="prose max-w-none text-slate-300 overflow-y-auto max-h-[500px] pr-2">
                            {rcaReport ? (
                              renderMarkdown(rcaReport)
                            ) : (
                              <div className="text-center py-10">
                                <p className="text-xs text-slate-500 italic">No RCA loaded. Hit Analyse to trigger Gemini network diagnostics.</p>
                              </div>
                            )}
                          </div>
                        )}
                      </div>

                      {/* Left Column Card 2: AI-Powered TAC Intelligence Vendor CLI Generator */}
                      <div className="bg-slate-900/20 border border-slate-900 rounded-xl p-5 flex flex-col gap-4">
                        <div className="flex items-center justify-between border-b border-slate-900 pb-3">
                          <div className="flex items-center gap-2">
                            <Terminal className="h-4.5 w-4.5 text-cyan-400" />
                            <span className="text-xs font-semibold text-slate-200">
                              AI-Powered TAC Intelligence: Vendor CLI Generator
                            </span>
                          </div>
                          <span className="text-[10px] font-mono text-slate-500 uppercase tracking-widest font-semibold">
                            Triage Automation
                          </span>
                        </div>

                        {(() => {
                          const worstFlow = analysisResult.connections && analysisResult.connections.length > 0 ? analysisResult.connections[0] : null;
                          const worstSrcIp = worstFlow ? worstFlow.srcIp : '10.0.0.5';
                          const worstDstIp = worstFlow ? worstFlow.dstIp : '192.168.1.10';

                          const paCommands = `debug dataplane packet-diag set filter match source ${worstSrcIp} destination ${worstDstIp}\ndebug dataplane packet-diag set filter on\nshow counter global filter delta yes | match drop`;
                          const fortinetCommands = `diagnose debug flow filter saddr ${worstSrcIp}\ndiagnose debug flow filter daddr ${worstDstIp}\ndiagnose debug flow show function-name enable\ndiagnose debug enable\ndiagnose debug flow trace start 100`;

                          const activeCommands = firewallVendor === 'palo_alto' ? paCommands : fortinetCommands;

                          return (
                            <div className="flex flex-col gap-4">
                              <p className="text-[11px] text-slate-400 leading-relaxed font-sans">
                                Select your active security gateway vendor to automatically synthesize diagnostic dataplane packet flow tracer filters targeted at the worst-performing session flow: <strong className="font-mono text-cyan-300">{worstSrcIp} &rarr; {worstDstIp}</strong>.
                              </p>

                              {/* Vendor Selector dropdown */}
                              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-slate-950/60 p-3 rounded-lg border border-slate-900">
                                <div className="flex items-center gap-2">
                                  <label className="text-xs font-semibold text-slate-400">Select Firewall Vendor:</label>
                                  <select
                                    value={firewallVendor}
                                    onChange={(e) => setFirewallVendor(e.target.value as 'palo_alto' | 'fortinet')}
                                    className="bg-slate-900 border border-slate-800 text-xs font-semibold text-cyan-400 hover:text-cyan-300 rounded px-2 py-1 focus:outline-none focus:border-cyan-500 transition-colors cursor-pointer"
                                  >
                                    <option value="palo_alto">Palo Alto PAN-OS</option>
                                    <option value="fortinet">Fortinet FortiOS</option>
                                  </select>
                                </div>

                                <button
                                  type="button"
                                  onClick={() => {
                                    navigator.clipboard.writeText(activeCommands);
                                    setCopiedText(true);
                                    setTimeout(() => setCopiedText(false), 2000);
                                  }}
                                  className="px-3 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold rounded text-xs transition-colors shrink-0 flex items-center gap-1.5 cursor-pointer shadow-sm"
                                >
                                  {copiedText ? (
                                    <>
                                      <CheckCircle className="h-3.5 w-3.5" />
                                      <span>Copied!</span>
                                    </>
                                  ) : (
                                    <>
                                      <FileText className="h-3.5 w-3.5" />
                                      <span>Copy CLI Commands</span>
                                    </>
                                  )}
                                </button>
                              </div>

                              {/* CLI command display box */}
                              <div className="relative bg-slate-950 rounded-lg border border-slate-900 overflow-hidden">
                                <div className="flex items-center justify-between px-3 py-1.5 bg-slate-900/60 text-slate-500 font-mono text-[9px] border-b border-slate-950">
                                  <span>{firewallVendor === 'palo_alto' ? 'PAN-OS PACKET-DIAG' : 'FORTIOS FLOW-TRACE'}</span>
                                  <span className="text-[8px] uppercase tracking-wider text-cyan-500/80 font-bold">Interactive CLI Code</span>
                                </div>
                                <pre className="p-4 text-xs font-mono text-cyan-400/90 leading-relaxed overflow-x-auto whitespace-pre select-all bg-slate-950">
                                  <code>{activeCommands}</code>
                                </pre>
                              </div>
                            </div>
                          );
                        })()}
                      </div>
                    </div>

                    {/* Right Column: The Culprit Connections & Outage Summary */}
                    <div className="flex flex-col gap-6">
                      {/* D3.js Timeline Chart */}
                      <div className="bg-slate-900/10 border border-slate-900 rounded-xl p-5 flex flex-col gap-4">
                        <div className="flex items-center gap-2 border-b border-slate-900 pb-3">
                          <Activity className="h-4 w-4 text-cyan-400" />
                          <span className="text-xs font-semibold text-slate-200">
                            TCP Packet & Retransmission Timeline
                          </span>
                        </div>
                        <PacketTimelineChart packets={analysisResult.packets} />
                      </div>

                      {/* D3.js RTT Latency Chart */}
                      <div className="bg-slate-900/10 border border-slate-900 rounded-xl p-5 flex flex-col gap-4">
                        <div className="flex items-center gap-2 border-b border-slate-900 pb-3">
                          <Activity className="h-4 w-4 text-orange-400 animate-pulse" />
                          <span className="text-xs font-semibold text-slate-200">
                            TCP Stream Round-Trip Time (RTT) Latency
                          </span>
                        </div>
                        <TcpRttLatencyChart packets={analysisResult.packets} />
                      </div>

                      {/* Connection flows */}
                      <div className="bg-slate-900/10 border border-slate-900 rounded-xl p-5 flex flex-col gap-4">
                        <div className="flex items-center justify-between border-b border-slate-900 pb-3">
                          <div className="flex items-center gap-2">
                            <Sliders className="h-4 w-4 text-cyan-400" />
                            <span className="text-xs font-semibold text-slate-200">
                              The Culprit Flow Table (TCP Retransmission SLA)
                            </span>
                          </div>
                          <span className="text-[10px] text-slate-500 font-mono">Sorted by Packet Loss Volume</span>
                        </div>

                        <div className="overflow-x-auto">
                          <table className="w-full text-left text-xs border-collapse">
                            <thead>
                              <tr className="border-b border-slate-900 text-slate-500 font-medium">
                                <th className="py-2.5">Source IP</th>
                                <th className="py-2.5"></th>
                                <th className="py-2.5">Destination IP</th>
                                <th className="py-2.5 text-right">TCP Packets</th>
                                <th className="py-2.5 text-right">Drops</th>
                                <th className="py-2.5 text-right">Retran. Rate</th>
                              </tr>
                            </thead>
                            <tbody className="divide-y divide-slate-900">
                              {analysisResult.connections.map((c, i) => {
                                const isBreached = c.retransmissionRate > 1.0;
                                return (
                                  <tr key={i} className="hover:bg-slate-900/30 transition-colors">
                                    <td className="py-2.5 font-mono text-[11px] text-slate-300 tabular-nums font-medium">{c.srcIp}</td>
                                    <td className="py-2.5 text-slate-600"><ArrowRight className="h-3 w-3" /></td>
                                    <td className="py-2.5 font-mono text-[11px] text-slate-300 tabular-nums font-medium">{c.dstIp}</td>
                                    <td className="py-2.5 text-right font-mono text-slate-400 tabular-nums">{c.tcpPackets}</td>
                                    <td className="py-2.5 text-right font-mono text-red-400 tabular-nums font-semibold">{c.retransmissions}</td>
                                    <td className={`py-2.5 text-right font-mono tabular-nums font-semibold ${
                                      isBreached ? 'text-red-400' : 'text-emerald-400'
                                    }`}>
                                      {c.retransmissionRate.toFixed(2)}%
                                      {isBreached && (
                                        <span className="block text-[8px] font-sans font-normal text-red-500 uppercase">
                                          SLA Breach
                                        </span>
                                      )}
                                    </td>
                                  </tr>
                                );
                              })}
                              {analysisResult.connections.length === 0 && (
                                <tr>
                                  <td colSpan={6} className="py-8 text-center text-slate-500 italic">No connection flows detected in the upload packet stream.</td>
                                </tr>
                              )}
                            </tbody>
                          </table>
                        </div>
                      </div>

                      {/* Visual Graph Summary */}
                      <div className="bg-slate-900/10 border border-slate-900 rounded-xl p-5 flex flex-col gap-4">
                        <span className="text-xs font-semibold text-slate-200">
                          Captured Packet Protocol Distribution
                        </span>
                        
                        <div className="flex flex-col gap-3">
                          {Object.entries(analysisResult.protocolCounts)
                            .filter(([_, val]) => val > 0)
                            .map(([proto, val]) => {
                              const percentage = (val / analysisResult.totalPackets) * 100;
                              let barColor = 'bg-cyan-500';
                              if (proto === 'TCP') barColor = 'bg-blue-500';
                              else if (proto === 'DNS') barColor = 'bg-purple-500';
                              else if (proto === 'HTTP' || proto === 'FTP') barColor = 'bg-amber-500';
                              else if (proto === 'ARP') barColor = 'bg-emerald-500';

                              return (
                                <div key={proto} className="flex flex-col gap-1">
                                  <div className="flex justify-between text-[11px] text-slate-400 font-mono">
                                    <span>{proto}</span>
                                    <span className="tabular-nums font-medium">{val} packets ({percentage.toFixed(1)}%)</span>
                                  </div>
                                  <div className="w-full h-1.5 bg-slate-900 rounded overflow-hidden">
                                    <div className={`h-full ${barColor}`} style={{ width: `${percentage}%` }}></div>
                                  </div>
                                </div>
                              );
                            })}
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {/* TAB 2: PACKETS (WIRESHARK CONSOLE) */}
              {activeTab === 'packets' && (
                <div className="flex flex-col gap-4 bg-slate-900/10 border border-slate-900 rounded-xl p-5">
                  <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-900 pb-4">
                    <div className="flex items-center gap-3 flex-wrap sm:flex-nowrap">
                      <div className="flex items-center gap-1.5">
                        <Terminal className="h-4 w-4 text-cyan-400" />
                        <span className="text-xs font-semibold text-slate-200">
                          Interactive Packet Stream Viewer
                        </span>
                      </div>
                      <button
                        onClick={handleDownloadFiltered}
                        title="Download currently filtered packet sequence as a new .pcap file"
                        className="flex items-center gap-1 px-2.5 py-1 text-[11px] font-medium bg-cyan-500/10 hover:bg-cyan-500/15 border border-cyan-500/25 hover:border-cyan-500/45 text-cyan-300 rounded transition-all duration-150 shrink-0"
                      >
                        <Download className="h-3 w-3" />
                        <span>Download Filtered ({filteredPackets.length})</span>
                      </button>
                    </div>

                    <div className="flex flex-wrap items-center gap-2">
                      {/* Search Bar */}
                      <div className="relative">
                        <Search className="absolute left-2.5 top-2 h-3.5 w-3.5 text-slate-500" />
                        <input
                          type="text"
                          placeholder="Search IPs, ports, info..."
                          value={searchTerm}
                          onChange={(e) => setSearchTerm(e.target.value)}
                          className="bg-slate-950 border border-slate-850 hover:border-slate-800 text-xs text-slate-300 rounded pl-8 pr-3 py-1.5 focus:outline-none focus:border-cyan-500 transition-colors w-48"
                        />
                      </div>

                      {/* Protocol filter tabs */}
                      <div className="flex gap-1 p-1 bg-slate-950 rounded border border-slate-900">
                        {['ALL', 'TCP', 'UDP', 'DNS', 'HTTP', 'FTP', 'RETRANSMISSION'].map((f) => (
                          <button
                            key={f}
                            onClick={() => {
                              setProtocolFilter(f);
                              setExpandedPacketIndex(null);
                            }}
                            className={`px-2 py-1 text-[10px] font-mono rounded transition-colors ${
                              protocolFilter === f
                                ? 'bg-slate-900 text-cyan-400 font-semibold'
                                : 'text-slate-500 hover:text-slate-300'
                            }`}
                          >
                            {f}
                          </button>
                        ))}
                      </div>
                    </div>
                  </div>

                  {/* Advanced Logical Query Builder Drawer */}
                  <div className="flex flex-col gap-3">
                    <div className="flex items-center justify-between bg-slate-950/40 border border-slate-900 rounded-lg px-4 py-2 text-xs">
                      <div className="flex items-center gap-2">
                        <Sliders className="h-3.5 w-3.5 text-cyan-400" />
                        <span className="font-semibold text-slate-300">Advanced logical query builder</span>
                        {filterRules.length > 0 && (
                          <span className="text-[9px] font-mono text-cyan-400 bg-cyan-500/10 px-1.5 py-0.5 rounded border border-cyan-500/20 font-semibold uppercase tracking-wider">
                            {filterRules.length} Active Rules ({filterConnector})
                          </span>
                        )}
                      </div>
                      <div className="flex items-center gap-3">
                        <button
                          type="button"
                          onClick={() => setIsFilterBuilderOpen(!isFilterBuilderOpen)}
                          className="text-[11px] font-semibold text-cyan-400 hover:text-cyan-300 transition-colors cursor-pointer"
                        >
                          {isFilterBuilderOpen ? 'Hide Builder' : 'Open Query Builder'}
                        </button>
                      </div>
                    </div>

                    {isFilterBuilderOpen && (
                      <div className="bg-slate-950 border border-slate-900 rounded-xl p-4 flex flex-col gap-4">
                        {/* Preset Queries */}
                        <div className="flex flex-wrap items-center gap-2 text-xs border-b border-slate-900 pb-3">
                          <span className="text-slate-500 font-medium text-[11px]">Diagnostic Presets:</span>
                          <button
                            type="button"
                            onClick={() => applyFilterPreset('syn_loss')}
                            className="px-2.5 py-1 bg-slate-900 hover:bg-slate-850 border border-slate-850 hover:border-slate-750 text-slate-300 rounded text-[10px] font-medium transition-colors cursor-pointer"
                          >
                            Find TCP SYN Packet Loss Drops
                          </button>
                          <button
                            type="button"
                            onClick={() => applyFilterPreset('plaintext')}
                            className="px-2.5 py-1 bg-slate-900 hover:bg-slate-850 border border-slate-850 hover:border-slate-750 text-slate-300 rounded text-[10px] font-medium transition-colors cursor-pointer"
                          >
                            Identify Plaintext HTTP Auth Leaks
                          </button>
                          <button
                            type="button"
                            onClick={() => applyFilterPreset('payment_fail')}
                            className="px-2.5 py-1 bg-slate-900 hover:bg-slate-850 border border-slate-850 hover:border-slate-750 text-slate-300 rounded text-[10px] font-medium transition-colors cursor-pointer"
                          >
                            Failing Payment Resolutions (RCODE != 0)
                          </button>
                        </div>

                        {/* Rule lines */}
                        <div className="flex flex-col gap-2.5">
                          {filterRules.map((rule, idx) => (
                            <div key={rule.id} className="flex flex-wrap items-center gap-2 text-xs bg-slate-900/30 p-2.5 rounded-lg border border-slate-900">
                              {/* Connector indicator for subsequent rows */}
                              {idx > 0 ? (
                                <span className="text-[10px] font-mono font-bold text-cyan-400 uppercase bg-cyan-500/5 px-2 py-1 rounded border border-cyan-500/10 select-none">
                                  {filterConnector}
                                </span>
                              ) : (
                                <span className="text-[10px] font-mono font-bold text-slate-500 uppercase bg-slate-900 px-2 py-1 rounded border border-slate-850 select-none">
                                  IF
                                </span>
                              )}

                              {/* Field Select */}
                              <select
                                value={rule.field}
                                onChange={(e) => updateFilterRule(rule.id, { field: e.target.value })}
                                className="bg-slate-950 border border-slate-850 hover:border-slate-800 text-slate-300 rounded px-2.5 py-1.5 focus:outline-none focus:border-cyan-500 transition-colors font-mono text-[11px]"
                              >
                                <option value="ip.src">ip.src (Source IP)</option>
                                <option value="ip.dst">ip.dst (Destination IP)</option>
                                <option value="ip.len">ip.len (Frame Length)</option>
                                <option value="ip.ttl">ip.ttl (Time to Live)</option>
                                <option value="tcp.srcport">tcp.srcport (Src Port)</option>
                                <option value="tcp.dstport">tcp.dstport (Dst Port)</option>
                                <option value="tcp.flags.syn">tcp.flags.syn (SYN Flag)</option>
                                <option value="tcp.flags.ack">tcp.flags.ack (ACK Flag)</option>
                                <option value="tcp.flags.fin">tcp.flags.fin (FIN Flag)</option>
                                <option value="tcp.flags.rst">tcp.flags.rst (RST Flag)</option>
                                <option value="tcp.retransmission">tcp.retransmission (Retrans.)</option>
                                <option value="dns.qry.name">dns.qry.name (DNS Target)</option>
                                <option value="dns.rcode">dns.rcode (DNS Return Code)</option>
                                <option value="protocol">protocol (Service Protocol)</option>
                                <option value="info">info (Info String)</option>
                              </select>

                              {/* Operator Select */}
                              <select
                                value={rule.operator}
                                onChange={(e) => updateFilterRule(rule.id, { operator: e.target.value as any })}
                                className="bg-slate-950 border border-slate-850 hover:border-slate-800 text-slate-300 rounded px-2.5 py-1.5 focus:outline-none focus:border-cyan-500 transition-colors font-mono text-[11px]"
                              >
                                <option value="==">== (Equals)</option>
                                <option value="!=">!= (Not Equals)</option>
                                <option value="contains">contains (Substring)</option>
                                <option value=">">&gt; (Greater than)</option>
                                <option value="<">&lt; (Less than)</option>
                              </select>

                              {/* Rule Value Input */}
                              {rule.field.includes('flags') || rule.field === 'tcp.retransmission' ? (
                                <select
                                  value={rule.value}
                                  onChange={(e) => updateFilterRule(rule.id, { value: e.target.value })}
                                  className="bg-slate-950 border border-slate-850 hover:border-slate-800 text-slate-300 rounded px-2.5 py-1.5 focus:outline-none focus:border-cyan-500 transition-colors font-mono text-[11px]"
                                >
                                  <option value="">-- Choose Boolean --</option>
                                  <option value="true">True</option>
                                  <option value="false">False</option>
                                </select>
                              ) : (
                                <input
                                  type="text"
                                  placeholder="Enter query value..."
                                  value={rule.value}
                                  onChange={(e) => updateFilterRule(rule.id, { value: e.target.value })}
                                  className="flex-1 min-w-[120px] bg-slate-950 border border-slate-850 hover:border-slate-800 text-slate-300 rounded px-2.5 py-1.5 focus:outline-none focus:border-cyan-500 transition-colors font-mono text-[11px]"
                                />
                              )}

                              {/* Delete Rule button */}
                              <button
                                type="button"
                                onClick={() => removeFilterRule(rule.id)}
                                className="p-1 hover:bg-slate-800 text-slate-500 hover:text-red-400 rounded transition-colors cursor-pointer text-xs"
                                title="Delete Rule condition"
                              >
                                ✕
                              </button>
                            </div>
                          ))}

                          {filterRules.length === 0 && (
                            <div className="text-center py-6 border border-dashed border-slate-900 rounded-lg">
                              <p className="text-slate-500 text-xs italic">No logical query rules added yet. Click "+ Add Rule" or choose an outage preset to start.</p>
                            </div>
                          )}
                        </div>

                        {/* Builder Controls */}
                        <div className="flex flex-wrap items-center justify-between gap-3 border-t border-slate-900 pt-3 text-xs">
                          <div className="flex items-center gap-4">
                            {/* Connector selection */}
                            <div className="flex items-center gap-1.5">
                              <span className="text-slate-500 font-medium text-[11px]">Join Conditions:</span>
                              <div className="flex rounded border border-slate-850 overflow-hidden font-mono text-[11px]">
                                <button
                                  type="button"
                                  onClick={() => setFilterConnector('AND')}
                                  className={`px-2 py-1 transition-colors cursor-pointer ${filterConnector === 'AND' ? 'bg-cyan-600 text-slate-950 font-bold' : 'bg-slate-950 hover:bg-slate-900 text-slate-400'}`}
                                >
                                  AND
                                </button>
                                <button
                                  type="button"
                                  onClick={() => setFilterConnector('OR')}
                                  className={`px-2 py-1 transition-colors cursor-pointer ${filterConnector === 'OR' ? 'bg-cyan-600 text-slate-950 font-bold' : 'bg-slate-950 hover:bg-slate-900 text-slate-400'}`}
                                >
                                  OR
                                </button>
                              </div>
                            </div>
                          </div>

                          <div className="flex items-center gap-2">
                            <button
                              type="button"
                              onClick={addFilterRule}
                              className="px-3 py-1.5 bg-slate-900 hover:bg-slate-850 border border-slate-850 hover:border-slate-750 text-cyan-400 font-semibold rounded text-xs transition-colors cursor-pointer"
                            >
                              + Add Rule
                            </button>
                            <button
                              type="button"
                              onClick={clearFilterRules}
                              className="px-3 py-1.5 bg-slate-900 hover:bg-slate-850 border border-slate-850 hover:border-slate-750 text-slate-400 rounded text-xs transition-colors cursor-pointer"
                            >
                              Clear All
                            </button>
                          </div>
                        </div>
                      </div>
                    )}
                  </div>

                  {/* Packet list stream grid */}
                  <div className="overflow-x-auto max-h-[500px]">
                    <table className="w-full text-left text-xs border-collapse">
                      <thead>
                        <tr className="border-b border-slate-900 text-slate-500 font-medium font-mono">
                          <th className="py-2 px-3 w-16">No.</th>
                          <th className="py-2 px-3 w-28">Time (ms)</th>
                          <th className="py-2 px-3 w-40">Source IP</th>
                          <th className="py-2 px-3 w-40">Destination IP</th>
                          <th className="py-2 px-3 w-24">Protocol</th>
                          <th className="py-2 px-3">Info Summary</th>
                          <th className="py-2 px-3 w-48 text-right">Anomaly & Threat Rules</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-900 font-mono text-[11px]">
                        {filteredPackets.map((pkt) => {
                          const isExpanded = expandedPacketIndex === pkt.index;
                          const anomalyBadge = getPacketAnomalyBadge(pkt);
                          let protocolBadgeColor = 'text-slate-400';
                          if (pkt.protocol === 'TCP') protocolBadgeColor = 'text-blue-400';
                          else if (pkt.protocol === 'DNS') protocolBadgeColor = 'text-purple-400';
                          else if (pkt.protocol === 'HTTP' || pkt.protocol === 'FTP') protocolBadgeColor = 'text-amber-400';
                          else if (pkt.protocol === 'ARP') protocolBadgeColor = 'text-emerald-400';

                          return (
                            <React.Fragment key={pkt.index}>
                              <tr
                                onClick={() => setExpandedPacketIndex(isExpanded ? null : pkt.index)}
                                className={`cursor-pointer transition-colors ${
                                  isExpanded ? 'bg-slate-900' : 'hover:bg-slate-900/30'
                                } ${
                                  pkt.isRetransmission ? 'bg-red-950/10 text-red-300' : ''
                                }`}
                              >
                                <td className="py-2.5 px-3 tabular-nums">{pkt.index + 1}</td>
                                <td className="py-2.5 px-3 tabular-nums">{pkt.timestamp.toFixed(2)}</td>
                                <td className="py-2.5 px-3 tabular-nums font-medium text-slate-300">{pkt.srcIp}</td>
                                <td className="py-2.5 px-3 tabular-nums font-medium text-slate-300">{pkt.dstIp}</td>
                                <td className={`py-2.5 px-3 font-semibold ${protocolBadgeColor}`}>{pkt.protocol}</td>
                                <td className="py-2.5 px-3 text-slate-300 max-w-lg truncate">
                                  {pkt.info}
                                </td>
                                <td className="py-2.5 px-3 text-right">
                                  {anomalyBadge ? (
                                    <div className="flex items-center justify-end gap-1.5" onClick={(e) => e.stopPropagation()}>
                                      <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold border ${anomalyBadge.color}`}>
                                        {anomalyBadge.label}
                                      </span>
                                      <button
                                        type="button"
                                        onClick={() => handleGenerateIdsRule(pkt)}
                                        title="Synthesize Suricata IDS & SIEM Sigma rules for this flagged threat signature"
                                        className="flex items-center gap-1 px-2 py-0.5 bg-rose-500/15 hover:bg-rose-500/25 border border-rose-500/30 hover:border-rose-500/50 text-rose-300 rounded font-semibold text-[10px] transition-all cursor-pointer shadow-sm hover:scale-[1.02] active:scale-[0.98]"
                                      >
                                        <Sparkles className="h-2.5 w-2.5 text-rose-400" />
                                        <span>Generate IDS Rule</span>
                                      </button>
                                    </div>
                                  ) : (
                                    <div className="flex items-center justify-end" onClick={(e) => e.stopPropagation()}>
                                      <button
                                        type="button"
                                        onClick={() => handleGenerateIdsRule(pkt)}
                                        title="Synthesize custom IDS rule for this packet"
                                        className="opacity-50 hover:opacity-100 flex items-center gap-1 px-1.5 py-0.5 bg-slate-900 hover:bg-slate-850 border border-slate-800 hover:border-slate-700 text-slate-400 hover:text-slate-200 rounded text-[9px] font-medium transition-all cursor-pointer"
                                      >
                                        <Code className="h-2.5 w-2.5 text-cyan-400" />
                                        <span>IDS Rule</span>
                                      </button>
                                    </div>
                                  )}
                                </td>
                              </tr>

                              {/* Expanded detailed skeuomorphic parser */}
                              {isExpanded && (
                                <tr>
                                  <td colSpan={7} className="bg-slate-950 p-4 border border-slate-900">
                                    <div className="flex flex-col gap-4">
                                      <div className="flex items-center gap-1.5 border-b border-slate-900 pb-2">
                                        <FileText className="h-4 w-4 text-cyan-400" />
                                        <span className="text-xs font-semibold text-slate-200">Frame Decoded Structure</span>
                                      </div>

                                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                                        {/* Frame Hierarchy details */}
                                        <div className="flex flex-col gap-2 bg-slate-900/30 p-3 rounded-lg border border-slate-900">
                                          <div className="flex flex-col">
                                            <span className="text-[10px] text-slate-500 font-bold uppercase">Frame Link layer (Ethernet Frame)</span>
                                            <span className="text-slate-300 text-[11px] mt-0.5">Destination MAC: 00:11:22:33:44:55 · Source MAC: 00:50:56:c0:00:08 · EtherType: IPv4 (0x0800)</span>
                                          </div>

                                          <div className="flex flex-col border-t border-slate-900 pt-1.5">
                                            <span className="text-[10px] text-slate-500 font-bold uppercase">Internet Protocol Version 4</span>
                                            <span className="text-slate-300 text-[11px] mt-0.5">Source IP: {pkt.srcIp} · Destination IP: {pkt.dstIp} · Total Header Length: 20 Bytes · TTL: 64</span>
                                          </div>

                                          <div className="flex flex-col border-t border-slate-900 pt-1.5">
                                            <span className="text-[10px] text-slate-500 font-bold uppercase">Transmission Control protocol / UDP</span>
                                            <span className="text-slate-300 text-[11px] mt-0.5">
                                              Source Port: {pkt.srcPort || 'N/A'} · Destination Port: {pkt.dstPort || 'N/A'}
                                              {pkt.tcpSeq !== undefined && ` · Sequence Number: ${pkt.tcpSeq} · Acknowledgment Number: ${pkt.tcpAck}`}
                                            </span>
                                          </div>
                                        </div>

                                        {/* Packet Summary HEX payload details */}
                                        <div className="flex flex-col gap-3 bg-slate-900/30 p-3 rounded-lg border border-slate-900">
                                          <div className="flex flex-col gap-1">
                                            <span className="text-[10px] text-slate-500 font-bold uppercase">Decoded Packet Payload Text Dump</span>
                                            <div className="p-2 bg-slate-950 border border-slate-900 rounded font-mono text-[10px] text-emerald-400 overflow-x-auto select-all max-h-[80px] leading-relaxed whitespace-pre-wrap">
                                              {pkt.info}
                                            </div>
                                          </div>

                                          <div className="flex flex-col gap-1 border-t border-slate-900 pt-2">
                                            <span className="text-[10px] text-slate-500 font-bold uppercase">Raw Hexadecimal Byte Map Viewer</span>
                                            <div className="p-2 bg-slate-950 border border-slate-900 rounded font-mono text-[9px] text-cyan-400 overflow-x-auto select-all max-h-[120px] leading-tight whitespace-pre">
                                              {generateHexDump(pkt.info, pkt)}
                                            </div>
                                          </div>

                                          <div className="flex flex-col gap-1 border-t border-slate-900 pt-2">
                                            <span className="text-[10px] text-slate-500 font-bold uppercase mb-1">Payload Forensic Extraction Utilities</span>
                                            <div className="flex flex-wrap gap-2">
                                              <button
                                                type="button"
                                                onClick={() => handleGenerateIdsRule(pkt)}
                                                className="flex-1 min-w-[170px] flex items-center justify-center gap-1.5 py-1.5 px-2 bg-rose-600/15 hover:bg-rose-600/25 border border-rose-500/30 hover:border-rose-500/50 text-rose-300 rounded font-semibold text-[10px] transition-all cursor-pointer shadow-sm hover:scale-[1.01]"
                                              >
                                                <Sparkles className="h-3 w-3 text-rose-400" />
                                                <span>Generate IDS Rule (Suricata & Sigma)</span>
                                              </button>
                                              <button
                                                type="button"
                                                onClick={() => {
                                                  // Generate report content
                                                  const metadata = `AUTO-TAC EXTRACTED FORENSIC PACKET PAYLOAD\n==============================================\nPacket Index: ${pkt.index + 1}\nTimestamp: ${pkt.timestamp.toFixed(2)} ms\nLength: ${pkt.length} Bytes\nProtocol: ${pkt.protocol}\nSource IP: ${pkt.srcIp}${pkt.srcPort ? `:${pkt.srcPort}` : ''}\nDestination IP: ${pkt.dstIp}${pkt.dstPort ? `:${pkt.dstPort}` : ''}\nIP Identification (IP ID): ${pkt.ipId !== undefined ? `0x${pkt.ipId.toString(16).toUpperCase()} (${pkt.ipId})` : 'N/A'}\nTTL: ${pkt.ttl || 'N/A'}\n${pkt.tcpSeq !== undefined ? `TCP Sequence: ${pkt.tcpSeq}\nTCP Acknowledgment: ${pkt.tcpAck}` : ''}\n==============================================\n\nRAW EXTRACTED PAYLOAD TEXT DUMP:\n----------------------------------------------\n${pkt.info}\n\n${pkt.plaintextCredentials ? `EXTRACTED CREDENTIALS FORENSIC:\n----------------------------------------------\nService: ${pkt.plaintextCredentials.service}\nType: ${pkt.plaintextCredentials.type}\nCredential Value: ${pkt.plaintextCredentials.value}\n` : ''}\n${pkt.dnsQuery ? `EXTRACTED DNS QUERY FORENSIC:\n----------------------------------------------\nQuery Domain: ${pkt.dnsQuery.domain}\nType: ${pkt.dnsQuery.type}\nIs Response: ${pkt.dnsQuery.isResponse}\nResponse Code: ${pkt.dnsQuery.rcodeName} (${pkt.dnsQuery.rcode})\nTTL: ${pkt.dnsQuery.dnsTtl !== undefined ? `${pkt.dnsQuery.dnsTtl}s` : 'N/A'}\n` : ''}\nHEXADECIMAL BYTE MAP REPRESENTATION:\n----------------------------------------------\n${generateHexDump(pkt.info, pkt)}\n`;
                                                  const blob = new Blob([metadata], { type: 'text/plain;charset=utf-8' });
                                                  const url = URL.createObjectURL(blob);
                                                  const link = document.createElement('a');
                                                  link.href = url;
                                                  link.download = `autotac_payload_packet_${pkt.index + 1}.txt`;
                                                  document.body.appendChild(link);
                                                  link.click();
                                                  document.body.removeChild(link);
                                                  URL.revokeObjectURL(url);
                                                }}
                                                className="flex-1 min-w-[150px] flex items-center justify-center gap-1.5 py-1.5 px-2 bg-cyan-600/10 hover:bg-cyan-600/15 border border-cyan-500/20 hover:border-cyan-500/35 text-cyan-300 rounded font-semibold text-[10px] transition-all cursor-pointer shadow-sm"
                                              >
                                                <Download className="h-3 w-3" />
                                                <span>Extract Report (.txt)</span>
                                              </button>
                                              <button
                                                type="button"
                                                onClick={() => {
                                                  const encoder = new TextEncoder();
                                                  const data = encoder.encode(pkt.info);
                                                  const blob = new Blob([data], { type: 'application/octet-stream' });
                                                  const url = URL.createObjectURL(blob);
                                                  const link = document.createElement('a');
                                                  link.href = url;
                                                  link.download = `autotac_payload_packet_${pkt.index + 1}.bin`;
                                                  document.body.appendChild(link);
                                                  link.click();
                                                  document.body.removeChild(link);
                                                  URL.revokeObjectURL(url);
                                                }}
                                                className="flex-1 min-w-[140px] flex items-center justify-center gap-1.5 py-1.5 px-2 bg-purple-600/10 hover:bg-purple-600/15 border border-purple-500/20 hover:border-purple-500/35 text-purple-300 rounded font-semibold text-[10px] transition-all cursor-pointer shadow-sm"
                                              >
                                                <Download className="h-3 w-3" />
                                                <span>Raw Binary (.bin)</span>
                                              </button>
                                            </div>
                                          </div>
                                        </div>
                                      </div>
                                    </div>
                                  </td>
                                </tr>
                              )}
                            </React.Fragment>
                          );
                        })}
                        {filteredPackets.length === 0 && (
                          <tr>
                            <td colSpan={7} className="py-12 text-center text-slate-500 italic">No packet streams found matching criteria.</td>
                          </tr>
                        )}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {/* TAB 3: DNS HEALTH LOGS */}
              {activeTab === 'dns' && (
                <div className="flex flex-col gap-6">
                  {analysisResult.dnsAnomalies.length > 0 && (
                    <DnsChordDiagram anomalies={analysisResult.dnsAnomalies} />
                  )}

                  <div className="bg-slate-900/10 border border-slate-900 rounded-xl p-5 flex flex-col gap-4">
                    <div className="flex items-center justify-between border-b border-slate-900 pb-3">
                      <div className="flex items-center gap-2">
                        <Globe className="h-4 w-4 text-cyan-400" />
                        <span className="text-xs font-semibold text-slate-200">
                          DNS Resolution Anomalies (ServFail / NXDomain Errors)
                        </span>
                      </div>
                      <span className="text-[10px] text-red-400 font-mono font-semibold animate-pulse">
                        {analysisResult.dnsFailureCount} Anomalies Flagged
                      </span>
                    </div>

                    <div className="overflow-x-auto">
                      <table className="w-full text-left text-xs border-collapse">
                        <thead>
                          <tr className="border-b border-slate-900 text-slate-500 font-medium font-mono">
                            <th className="py-2.5">Time Offset</th>
                            <th className="py-2.5">Client IP</th>
                            <th className="py-2.5">DNS Server</th>
                            <th className="py-2.5">Queried Domain Target</th>
                            <th className="py-2.5">Response Code</th>
                            <th className="py-2.5">Severity</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-900 font-mono text-[11px]">
                          {analysisResult.dnsAnomalies.map((dns, i) => (
                            <tr key={i} className="hover:bg-slate-900/30 transition-colors">
                              <td className="py-2.5 tabular-nums text-slate-400">{new Date(dns.timestamp).toISOString().split('T')[1].slice(0, -1)}s</td>
                              <td className="py-2.5 text-slate-300 font-medium">{dns.srcIp}</td>
                              <td className="py-2.5 text-slate-400">{dns.dstIp}</td>
                              <td className="py-2.5 text-cyan-300 font-medium">{dns.dnsQuery?.domain}</td>
                              <td className="py-2.5 text-amber-400 font-semibold">{dns.dnsQuery?.rcodeName} (RCODE {dns.dnsQuery?.rcode})</td>
                              <td className="py-2.5">
                                <span className="px-1.5 py-0.5 text-[8px] font-sans font-semibold rounded-sm bg-amber-500/10 border border-amber-500/20 text-amber-400 uppercase">
                                  Warning
                                </span>
                              </td>
                            </tr>
                          ))}
                          {analysisResult.dnsAnomalies.length === 0 && (
                            <tr>
                              <td colSpan={6} className="py-12 text-center text-slate-500 italic">Perfect DNS Resolution records! No ServFail or NXDomain responses identified.</td>
                            </tr>
                          )}
                        </tbody>
                      </table>
                    </div>
                  </div>

                  {/* DNS TTL Evasion & Hijacking Diagnostics Panel */}
                  <div className="bg-slate-900/10 border border-slate-900 rounded-xl p-5 flex flex-col gap-4">
                    <div className="flex items-center justify-between border-b border-slate-900 pb-3">
                      <div className="flex items-center gap-2">
                        <AlertTriangle className="h-4 w-4 text-red-400 animate-pulse" />
                        <span className="text-xs font-semibold text-slate-200">
                          DNS TTL Evasion & Hijacking Diagnostics (Low Time-To-Live Check)
                        </span>
                      </div>
                      <span className="text-[10px] text-red-400 font-mono font-semibold uppercase animate-pulse">
                        {(analysisResult.packets || []).filter(p => p.protocol === 'DNS' && p.dnsQuery && p.dnsQuery.isResponse && p.dnsQuery.dnsTtl !== undefined && p.dnsQuery.dnsTtl <= 10).length} High-Risk Records
                      </span>
                    </div>

                    <div className="overflow-x-auto">
                      <table className="w-full text-left text-xs border-collapse">
                        <thead>
                          <tr className="border-b border-slate-900 text-slate-500 font-medium font-mono">
                            <th className="py-2.5">Time Offset</th>
                            <th className="py-2.5">Client IP</th>
                            <th className="py-2.5">DNS Server</th>
                            <th className="py-2.5">Queried Domain Target</th>
                            <th className="py-2.5 text-right">DNS TTL</th>
                            <th className="py-2.5">Risk Analysis Description</th>
                            <th className="py-2.5">Severity</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-900 font-mono text-[11px] tabular-nums">
                          {(() => {
                            const lowTtlDnsPackets = (analysisResult.packets || []).filter(
                              p => p.protocol === 'DNS' && p.dnsQuery && p.dnsQuery.isResponse && p.dnsQuery.dnsTtl !== undefined && p.dnsQuery.dnsTtl <= 10
                            );
                            return lowTtlDnsPackets.map((dns, i) => (
                              <tr key={i} className="hover:bg-slate-900/30 transition-colors text-red-200">
                                <td className="py-2.5 text-slate-400">{new Date(dns.timestamp).toISOString().split('T')[1].slice(0, -1)}s</td>
                                <td className="py-2.5 text-slate-300 font-medium">{dns.srcIp}</td>
                                <td className="py-2.5 text-slate-400">{dns.dstIp}</td>
                                <td className="py-2.5 text-cyan-300 font-medium">{dns.dnsQuery?.domain}</td>
                                <td className="py-2.5 text-right text-red-400 font-bold">{dns.dnsQuery?.dnsTtl}s</td>
                                <td className="py-2.5 text-slate-400 font-sans text-xs">
                                  Low TTL ({dns.dnsQuery?.dnsTtl}s) indicates possible fast-flux DNS evasion, firewall subversion, or active IP hijacking.
                                </td>
                                <td className="py-2.5 font-sans">
                                  <span className="px-1.5 py-0.5 text-[8px] font-semibold rounded bg-red-500/10 border border-red-500/20 text-red-400 uppercase animate-pulse">
                                    Critical Risk
                                  </span>
                                </td>
                              </tr>
                            ));
                          })()}
                          {((analysisResult.packets || []).filter(p => p.protocol === 'DNS' && p.dnsQuery && p.dnsQuery.isResponse && p.dnsQuery.dnsTtl !== undefined && p.dnsQuery.dnsTtl <= 10).length) === 0 && (
                            <tr>
                              <td colSpan={7} className="py-12 text-center text-slate-500 italic">No low-TTL DNS hijacking or evasion traces detected in the active packet stream.</td>
                            </tr>
                          )}
                        </tbody>
                      </table>
                    </div>
                  </div>
                </div>
              )}

              {/* TAB 4: SOC SECURITY VAULT */}
              {activeTab === 'security' && (
                <div className="flex flex-col gap-6">
                  <div className="bg-slate-900/10 border border-slate-900 rounded-xl p-5 flex flex-col gap-4">
                    <div className="flex items-center justify-between border-b border-slate-900 pb-3">
                      <div className="flex items-center gap-2">
                        <ShieldAlert className="h-4 w-4 text-red-400 animate-pulse" />
                        <span className="text-xs font-semibold text-slate-200">
                          SOC Plaintext Credential Leaks Vault (HTTP & FTP Risks)
                        </span>
                      </div>
                      {analysisResult.plaintextCredentialsCount > 0 ? (
                        <span className="text-[10px] text-red-400 bg-red-500/10 px-2 py-0.5 border border-red-500/25 rounded font-mono font-bold uppercase tracking-wider animate-pulse">
                          CRITICAL RISK LEAK DETECTED
                        </span>
                      ) : (
                        <span className="text-[10px] text-emerald-400 font-mono font-semibold">
                          Nominal Security Status
                        </span>
                      )}
                    </div>

                    <div className="overflow-x-auto">
                      <table className="w-full text-left text-xs border-collapse">
                        <thead>
                          <tr className="border-b border-slate-900 text-slate-500 font-medium font-mono">
                            <th className="py-2.5">Time Offset</th>
                            <th className="py-2.5">Client Host</th>
                            <th className="py-2.5">Server Destination</th>
                            <th className="py-2.5">Insecure Protocol</th>
                            <th className="py-2.5">Leak Mechanism</th>
                            <th className="py-2.5">Exposed Credential Data</th>
                            <th className="py-2.5 text-right">IDS Rule Synthesis</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-900 font-mono text-[11px]">
                          {analysisResult.plaintextCredentials.map((cred, i) => (
                            <tr key={i} className="hover:bg-slate-900/30 transition-colors text-red-200">
                              <td className="py-2.5 text-slate-400 tabular-nums">{new Date(cred.timestamp).toISOString().split('T')[1].slice(0, -1)}s</td>
                              <td className="py-2.5 text-slate-300 font-medium">{cred.srcIp}</td>
                              <td className="py-2.5 text-slate-400">{cred.dstIp}:{cred.dstPort}</td>
                              <td className="py-2.5 text-amber-500 font-semibold">{cred.plaintextCredentials?.service}</td>
                              <td className="py-2.5 text-slate-400 text-xs">{cred.plaintextCredentials?.type}</td>
                              <td className="py-2.5 text-red-400 font-semibold text-xs font-mono bg-red-500/5 px-2 rounded border border-red-500/10 max-w-sm truncate select-all">
                                {cred.plaintextCredentials?.value}
                              </td>
                              <td className="py-2.5 text-right">
                                <button
                                  type="button"
                                  onClick={() => handleGenerateIdsRule(cred)}
                                  className="inline-flex items-center gap-1 px-2.5 py-1 bg-rose-500/15 hover:bg-rose-500/25 border border-rose-500/30 hover:border-rose-500/50 text-rose-300 rounded font-semibold text-[10px] transition-all cursor-pointer shadow-sm hover:scale-[1.02]"
                                  title="Synthesize deployable Suricata IDS and Sigma rules for this credential leak"
                                >
                                  <Sparkles className="h-3 w-3 text-rose-400" />
                                  <span>Generate IDS Rule</span>
                                </button>
                              </td>
                            </tr>
                          ))}
                          {analysisResult.plaintextCredentials.length === 0 && (
                            <tr>
                              <td colSpan={7} className="py-12 text-center text-slate-500 italic">No unencrypted credentials or plain-text authorization strings detected in payloads.</td>
                            </tr>
                          )}
                        </tbody>
                      </table>
                    </div>
                  </div>
                </div>
              )}

              {/* TAB 5: BATCH COMPARISON VIEW */}
              {activeTab === 'batch' && (
                <div className="flex flex-col gap-6">
                  {/* Header / Sandbox trigger row */}
                  <div className="flex flex-wrap items-center justify-between gap-4 bg-slate-900/10 border border-slate-900 p-4 rounded-xl">
                    <div>
                      <h3 className="text-sm font-semibold text-white">Capture Batch Processing Console</h3>
                      <p className="text-[11px] text-slate-400 mt-0.5">Simultaneously profile and compare network diagnostics across multiple traces.</p>
                    </div>
                    <div className="flex gap-2">
                      <button
                        onClick={handleLoadBatchPreset}
                        className="px-3 py-1.5 bg-cyan-600/10 hover:bg-cyan-600/15 border border-cyan-500/20 text-cyan-400 hover:text-cyan-300 font-semibold rounded text-xs transition-colors shrink-0 flex items-center gap-1 cursor-pointer"
                      >
                        <Sliders className="h-3.5 w-3.5" />
                        <span>Compare Outage Presets (Batch Load)</span>
                      </button>
                      {batchResults.length > 0 && (
                        <button
                          onClick={() => {
                            setBatchResults([]);
                            setBatchRcaReport(null);
                          }}
                          className="px-3 py-1.5 bg-slate-900 hover:bg-slate-850 text-slate-400 border border-slate-800 rounded text-xs transition-colors cursor-pointer"
                        >
                          Clear Batch
                        </button>
                      )}
                    </div>
                  </div>

                  {batchResults.length === 0 ? (
                    <div className="flex flex-col items-center justify-center py-20 gap-4 bg-slate-900/10 border border-slate-900 rounded-2xl text-center max-w-xl mx-auto">
                      <Sliders className="h-10 w-10 text-slate-600 animate-pulse" />
                      <div>
                        <h4 className="text-xs font-semibold text-white">No Batch Captures Loaded</h4>
                        <p className="text-[11px] text-slate-400 leading-relaxed mt-1">
                          Select and upload **multiple PCAP files simultaneously** using the header upload button, or click the preset button above to compare our three outage scenarios.
                        </p>
                      </div>
                    </div>
                  ) : (
                    <>
                      {/* Comparative Matrix Table */}
                      <div className="bg-slate-900/10 border border-slate-900 rounded-xl p-5 flex flex-col gap-4">
                        <span className="text-xs font-semibold text-slate-200">
                          Consolidated Multi-Capture Comparative Matrix
                        </span>

                        <div className="overflow-x-auto">
                          <table className="w-full text-left text-xs border-collapse">
                            <thead>
                              <tr className="border-b border-slate-900 text-slate-500 font-medium font-mono">
                                <th className="py-2.5">Capture Name</th>
                                <th className="py-2.5 text-right">Packets</th>
                                <th className="py-2.5 text-right">Avg Frame</th>
                                <th className="py-2.5 text-right">Max MTU</th>
                                <th className="py-2.5 text-right">TCP Loss Rate</th>
                                <th className="py-2.5 text-right">DNS Failures</th>
                                <th className="py-2.5 text-right">Sec Leaks</th>
                                <th className="py-2.5 text-center">SLA Compliance</th>
                                <th className="py-2.5 text-right">Forensic Actions</th>
                              </tr>
                            </thead>
                            <tbody className="divide-y divide-slate-900 font-mono text-[11px] tabular-nums">
                              {batchResults.map((item) => {
                                const isBreached = item.result.globalRetransmissionRate > 1.0;
                                const isActive = analysisResult?.totalBytes === item.result.totalBytes && analysisResult?.totalPackets === item.result.totalPackets;
                                return (
                                  <tr key={item.id} className={`hover:bg-slate-900/30 transition-colors ${isActive ? 'bg-cyan-500/5' : ''}`}>
                                    <td className="py-3 font-sans text-xs text-slate-200 font-medium max-w-xs truncate" title={item.fileName}>
                                      {item.fileName}
                                    </td>
                                    <td className="py-3 text-right text-slate-300">{item.result.totalPackets.toLocaleString()}</td>
                                    <td className="py-3 text-right text-slate-400">{Math.round(item.result.captureProfiler?.averageFrameSize || 0)} B</td>
                                    <td className="py-3 text-right text-slate-400">{item.result.captureProfiler?.mtuAnalysis?.maxFrameSize || 0} B</td>
                                    <td className={`py-3 text-right font-semibold ${isBreached ? 'text-red-400' : 'text-emerald-400'}`}>
                                      {item.result.globalRetransmissionRate.toFixed(2)}%
                                    </td>
                                    <td className={`py-3 text-right ${item.result.dnsFailureCount > 0 ? 'text-amber-400 font-bold' : 'text-slate-500'}`}>
                                      {item.result.dnsFailureCount}
                                    </td>
                                    <td className={`py-3 text-right ${item.result.plaintextCredentialsCount > 0 ? 'text-red-400 font-bold' : 'text-slate-500'}`}>
                                      {item.result.plaintextCredentialsCount}
                                    </td>
                                    <td className="py-3 text-center font-sans">
                                      {isBreached ? (
                                        <span className="text-[9px] font-semibold text-red-400 uppercase">
                                          Breached SLA
                                        </span>
                                      ) : (
                                        <span className="text-[9px] font-semibold text-emerald-400 uppercase">
                                          Compliant
                                        </span>
                                      )}
                                    </td>
                                    <td className="py-3 text-right font-sans">
                                      <div className="flex justify-end gap-2">
                                        <button
                                          onClick={() => setAnalysisResult(item.result)}
                                          className={`px-2 py-1 text-[10px] font-bold rounded transition-colors ${
                                            isActive
                                              ? 'bg-cyan-500 text-slate-950 cursor-default shadow-sm'
                                              : 'bg-slate-900 hover:bg-slate-850 text-cyan-400 border border-slate-850 hover:border-slate-750 cursor-pointer shadow-sm'
                                          }`}
                                        >
                                          {isActive ? 'Active Stream' : 'Switch Focus'}
                                        </button>
                                        <button
                                          onClick={() => {
                                            const filtered = batchResults.filter(x => x.id !== item.id);
                                            setBatchResults(filtered);
                                            if (isActive && filtered.length > 0) {
                                              setAnalysisResult(filtered[0].result);
                                            }
                                          }}
                                          className="p-1 text-slate-500 hover:text-red-400 rounded transition-colors cursor-pointer text-xs"
                                        >
                                          ✕
                                        </button>
                                      </div>
                                    </td>
                                  </tr>
                                );
                              })}
                            </tbody>
                          </table>
                        </div>
                      </div>

                      {/* Split view: Consolidated Report and Controls */}
                      <div className="grid grid-cols-1 gap-6">
                        {/* Comparison AI Report Box */}
                        <div className="bg-slate-900/20 border border-slate-900 rounded-xl p-5 flex flex-col gap-4 relative">
                          <div className="flex items-center justify-between border-b border-slate-900 pb-3">
                            <div className="flex items-center gap-2">
                              <Cpu className="h-4 w-4 text-cyan-400" />
                              <span className="text-xs font-semibold text-slate-200">
                                Consolidated Batch Comparison AI Report
                              </span>
                            </div>
                            <span className="text-[10px] text-slate-500 font-mono">gemini-3.8-flash</span>
                          </div>

                          {/* Context steering form */}
                          <form onSubmit={handleUpdateBatchRcaContext} className="flex gap-2">
                            <input
                              type="text"
                              placeholder="Add diagnostic comparisons (e.g. 'Trace 1 is healthy pre-outage, Trace 2 is during outage')"
                              value={batchCustomContext}
                              onChange={(e) => setBatchCustomContext(e.target.value)}
                              className="flex-1 bg-slate-950 border border-slate-850 hover:border-slate-800 text-xs text-slate-300 rounded px-2.5 py-1.5 focus:outline-none focus:border-cyan-500 transition-colors"
                            />
                            <button
                              type="submit"
                              disabled={isBatchAiAnalyzing}
                              className="px-3 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold rounded text-xs transition-colors shrink-0 flex items-center gap-1 disabled:opacity-50 cursor-pointer"
                            >
                              <RefreshCw className={`h-3 w-3 ${isBatchAiAnalyzing ? 'animate-spin' : ''}`} />
                              <span>Compare Captures</span>
                            </button>
                          </form>

                          {isBatchAiAnalyzing ? (
                            <div className="flex flex-col gap-3 py-6">
                              <div className="h-3 w-3/4 bg-slate-850 animate-pulse rounded"></div>
                              <div className="h-3 w-5/6 bg-slate-850 animate-pulse rounded"></div>
                              <div className="h-3 w-1/2 bg-slate-850 animate-pulse rounded"></div>
                              <div className="h-3 w-2/3 bg-slate-850 animate-pulse rounded"></div>
                            </div>
                          ) : (
                            <div className="prose max-w-none text-slate-300 overflow-y-auto max-h-[500px] pr-2">
                              {batchRcaReport ? (
                                renderMarkdown(batchRcaReport)
                              ) : (
                                <div className="text-center py-10">
                                  <p className="text-xs text-slate-500 italic">No consolidated comparative report generated. Hit Compare Captures to analyze captures matrix.</p>
                                </div>
                              )}
                            </div>
                          )}
                        </div>
                      </div>
                    </>
                  )}
                </div>
              )}

              {/* TAB 6: NETWORK TOPOLOGY FORCE GRAPH */}
              {activeTab === 'topology' && (
                <div className="flex flex-col gap-6">
                  <div className="bg-slate-900/10 border border-slate-900 rounded-xl p-5 flex flex-col gap-4">
                    <div className="flex items-center justify-between border-b border-slate-900 pb-3">
                      <div className="flex items-center gap-2">
                        <Globe className="h-4 w-4 text-cyan-400 animate-pulse" />
                        <span className="text-sm font-semibold text-slate-200">
                          Automated Forensic Network Topology & Lateral Movement Mapper
                        </span>
                      </div>
                      <span className="text-[10px] font-mono text-slate-500 uppercase tracking-widest font-semibold">
                        D3.js Force-Directed Relation Graph
                      </span>
                    </div>
                    <NetworkTopologyGraph analysisResult={analysisResult} />
                  </div>
                </div>
              )}

              {/* TAB 7: LATENCY ARBITER */}
              {activeTab === 'latency' && (
                <div className="flex flex-col gap-6">
                  <div className="bg-slate-900/10 border border-slate-900 rounded-xl p-5 flex flex-col gap-4">
                    <div className="flex items-center justify-between border-b border-slate-900 pb-3">
                      <div className="flex items-center gap-2">
                        <Cpu className="h-4 w-4 text-cyan-400" />
                        <span className="text-sm font-semibold text-slate-200">
                          The Network vs. Application Latency Arbiter
                        </span>
                      </div>
                      <span className="text-[10px] font-mono text-slate-500 uppercase tracking-widest font-semibold">
                        SLA Segment Diagnostics
                      </span>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                      {/* Left Card: Network Handshake RTT */}
                      <div className="bg-slate-950 border border-slate-900 p-6 rounded-xl flex flex-col gap-3">
                        <span className="text-[11px] font-mono font-bold uppercase tracking-wider text-slate-500">
                          📡 Average Network Handshake RTT
                        </span>
                        <div className={`text-4xl font-bold font-mono tracking-tight tabular-nums ${
                          (analysisResult.averageHandshakeRtt || 0) > 150 ? 'text-red-400' : 'text-cyan-400'
                        }`}>
                          {(analysisResult.averageHandshakeRtt || 0).toFixed(2)} <span className="text-lg">ms</span>
                        </div>
                        <p className="text-[11px] text-slate-400 leading-relaxed font-sans mt-2">
                          Measures the physical packet propagation time delta of the TCP 3-way handshake (SYN-ACK packet timestamp minus client SYN packet timestamp). Perfect indicator of pure wire-level network transit latency.
                        </p>
                      </div>

                      {/* Right Card: Server TTFB */}
                      <div className="bg-slate-950 border border-slate-900 p-6 rounded-xl flex flex-col gap-3">
                        <span className="text-[11px] font-mono font-bold uppercase tracking-wider text-slate-500">
                          ⚙️ Average Server Time-To-First-Byte (TTFB)
                        </span>
                        <div className={`text-4xl font-bold font-mono tracking-tight tabular-nums ${
                          (analysisResult.averageTtfb || 0) > 500 ? 'text-red-400' : 'text-purple-400'
                        }`}>
                          {(analysisResult.averageTtfb || 0).toFixed(2)} <span className="text-lg">ms</span>
                        </div>
                        <p className="text-[11px] text-slate-400 leading-relaxed font-sans mt-2">
                          Measures the server's processing delay (time-delta from client completing an HTTP request until the server returns the first response byte). Crucial indicator of database or application thread processing delay.
                        </p>
                      </div>
                    </div>

                    {/* Arbiter Verdict Box */}
                    {(() => {
                      const rtt = analysisResult.averageHandshakeRtt || 0;
                      const ttfb = analysisResult.averageTtfb || 0;
                      let verdictText = "All Layers Nominal: Optimal transit and application response benchmarks.";
                      let verdictBg = "bg-cyan-500/5 border-cyan-500/20";
                      let verdictTextClass = "text-cyan-400";
                      let advice = "The network trace shows healthy parameters for both communication links and web services.";

                      if (ttfb > 500 && rtt < 50) {
                        verdictText = "Exonerate Network: Delay is localized to backend database/application processing.";
                        verdictBg = "bg-emerald-500/5 border-emerald-500/20";
                        verdictTextClass = "text-emerald-400";
                        advice = "The network connection is fast, but the server takes an exceptionally long time to build HTTP response objects. Troubleshoot server database connection pools or application execution code.";
                      } else if (rtt > 200) {
                        verdictText = "Network Transit Latency Detected: In-transit route congestion or queuing delay.";
                        verdictBg = "bg-red-500/5 border-red-500/20 animate-pulse";
                        verdictTextClass = "text-red-400";
                        advice = "Handshake latency is extremely slow, pointing directly to intermediate router congestion, low-tier satellite links, asymmetric route loops, or physical dropouts.";
                      } else if (ttfb > 500 || rtt > 150) {
                        verdictText = "Coexisting Degradation: Latency observed on both network and host layers.";
                        verdictBg = "bg-amber-500/5 border-amber-500/20";
                        verdictTextClass = "text-amber-400";
                        advice = "Both physical transit latency and host application server delays are elevated. Recommend full diagnostic overhaul of endpoints and intermediate gateway routers.";
                      }

                      return (
                        <div className={`border rounded-lg p-4 flex flex-col gap-2 mt-4 ${verdictBg}`}>
                          <h4 className={`text-xs font-bold font-mono uppercase tracking-wider ${verdictTextClass}`}>
                            ⚡ Root Cause Analysis Verdict: {verdictText}
                          </h4>
                          <p className="text-[11px] text-slate-300 leading-relaxed font-sans">
                            <strong>Forensic Diagnostics:</strong> {advice}
                          </p>
                        </div>
                      );
                    })()}
                  </div>
                </div>
              )}

              {/* TAB 8: TCP RESET MIDDLEBOX FINGERPRINTING */}
              {activeTab === 'middlebox' && (
                <div className="flex flex-col gap-6">
                  <div className="bg-slate-900/10 border border-slate-900 rounded-xl p-5 flex flex-col gap-4">
                    <div className="flex items-center justify-between border-b border-slate-900 pb-3">
                      <div className="flex items-center gap-2">
                        <ShieldAlert className="h-4 w-4 text-red-500" />
                        <span className="text-sm font-semibold text-slate-200">
                          TCP Reset (RST) Middlebox Fingerprinting Console
                        </span>
                      </div>
                      <span className="text-[10px] font-mono text-slate-500 uppercase tracking-widest font-semibold">
                        Layer-3 TTL Fingerprinting
                      </span>
                    </div>

                    <div className="bg-slate-950/40 border border-slate-900/60 p-4 rounded-lg flex flex-col gap-2">
                      <h4 className="text-xs font-semibold text-red-400 font-sans uppercase">Fingerprinting Methodology</h4>
                      <p className="text-[11px] text-slate-400 leading-relaxed font-sans">
                        When intermediate security devices (firewalls, IPS/IDS) kill a session, they inject spoofed TCP Reset (RST) packets. Because these injected packets are emitted locally from the inline device itself, their Time-To-Live (TTL) values do not experience standard transit routing decrements. By comparing the RST packet's TTL against standard baseline data packets of the same flow, we can fingerprint inline security devices.
                      </p>
                    </div>

                    {/* Stats counters */}
                    {(() => {
                      const fingerprints = analysisResult.rstFingerprints || [];
                      const firewallInjections = fingerprints.filter(f => f.verdict.includes('Firewall')).length;
                      const socketAborts = fingerprints.filter(f => f.verdict.includes('Crash')).length;

                      return (
                        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                          <div className="bg-slate-950 p-4 rounded-xl border border-slate-900 flex flex-col gap-1">
                            <span className="text-[10px] text-slate-500 font-bold uppercase tracking-wider">Total Reset Packets</span>
                            <span className="text-xl font-bold font-mono text-slate-100">{fingerprints.length}</span>
                          </div>
                          <div className="bg-slate-950 p-4 rounded-xl border border-slate-900 flex flex-col gap-1">
                            <span className="text-[10px] text-red-400 font-bold uppercase tracking-wider">Firewall Injected Resets</span>
                            <span className="text-xl font-bold font-mono text-red-400">{firewallInjections}</span>
                          </div>
                          <div className="bg-slate-950 p-4 rounded-xl border border-slate-900 flex flex-col gap-1">
                            <span className="text-[10px] text-cyan-400 font-bold uppercase tracking-wider">Socket Aborts / Crashes</span>
                            <span className="text-xl font-bold font-mono text-cyan-400">{socketAborts}</span>
                          </div>
                        </div>
                      );
                    })()}

                    {/* Reset logs table */}
                    <div className="overflow-x-auto">
                      <table className="w-full text-left text-xs border-collapse">
                        <thead>
                          <tr className="border-b border-slate-900 text-slate-500 font-medium font-mono">
                            <th className="py-2.5">Time Offset</th>
                            <th className="py-2.5">Source IP</th>
                            <th className="py-2.5"></th>
                            <th className="py-2.5">Destination IP</th>
                            <th className="py-2.5">TTL Delta Diagnostic</th>
                            <th className="py-2.5">Automated Verdict</th>
                            <th className="py-2.5 text-center">Threat Severity</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-900 font-mono text-[11px] tabular-nums">
                          {(analysisResult.rstFingerprints || []).map((f, i) => {
                            const isFirewall = f.verdict.includes('Firewall');
                            return (
                              <tr key={i} className={`hover:bg-slate-900/30 transition-colors ${isFirewall ? 'text-red-200' : 'text-cyan-200'}`}>
                                <td className="py-3 text-slate-400">
                                  {new Date(f.timestamp).toISOString().split('T')[1].slice(0, -1)}s
                                </td>
                                <td className="py-3 font-semibold">{f.srcIp}:{f.srcPort}</td>
                                <td className="py-3 text-slate-600"><ArrowRight className="h-3 w-3" /></td>
                                <td className="py-3 font-semibold">{f.dstIp}:{f.dstPort}</td>
                                <td className="py-3 text-slate-400">{f.ttlDeltaCheck}</td>
                                <td className={`py-3 font-semibold ${isFirewall ? 'text-red-400' : 'text-cyan-400'}`}>
                                  {f.verdict}
                                </td>
                                <td className="py-3 text-center">
                                  {isFirewall ? (
                                    <span className="px-1.5 py-0.5 text-[8px] font-sans font-semibold rounded bg-red-500/10 border border-red-500/20 text-red-400 uppercase animate-pulse">
                                      Critical Policy Block
                                    </span>
                                  ) : (
                                    <span className="px-1.5 py-0.5 text-[8px] font-sans font-semibold rounded bg-slate-900 border border-slate-800 text-slate-400 uppercase">
                                      Nominal Socket Abort
                                    </span>
                                  )}
                                </td>
                              </tr>
                            );
                          })}
                          {(!analysisResult.rstFingerprints || analysisResult.rstFingerprints.length === 0) && (
                            <tr>
                              <td colSpan={7} className="py-12 text-center text-slate-500 italic">No TCP connection terminate/reset signatures captured inside this trace.</td>
                            </tr>
                          )}
                        </tbody>
                      </table>
                    </div>
                  </div>
                </div>
              )}

              {/* TAB 9: TLS HANDSHAKE HEALTH & FATAL ALERTS */}
              {activeTab === 'tls' && (
                <div className="flex flex-col gap-6">
                  <div className="bg-slate-900/10 border border-slate-900 rounded-xl p-5 flex flex-col gap-4">
                    <div className="flex items-center justify-between border-b border-slate-900 pb-3">
                      <div className="flex items-center gap-2">
                        <Key className="h-4 w-4 text-purple-400" />
                        <span className="text-sm font-semibold text-slate-200">
                          TLS/SSL Handshake Failure & Fatal Alert Diagnostics
                        </span>
                      </div>
                      <span className="text-[10px] font-mono text-slate-500 uppercase tracking-widest font-semibold">
                        Encrypted Tunnel Forensic Analyzer
                      </span>
                    </div>

                    <div className="bg-slate-950/40 border border-slate-900/60 p-4 rounded-lg flex flex-col gap-2">
                      <h4 className="text-xs font-semibold text-purple-400 font-sans uppercase">TLS Decryption & Handshake Fingerprinting Methodology</h4>
                      <p className="text-[11px] text-slate-400 leading-relaxed font-sans">
                        TLS handshakes establish secure end-to-end encryption. Even when packets are encrypted, the initial <strong>Client Hello</strong> frame contains the unencrypted <strong>Server Name Indication (SNI)</strong> extension, revealing the target domain. If a handshake fails due to a cipher suite mismatch, expired certificate, or decryption block, the server triggers a <strong>TLS Fatal Alert Record</strong>. AutoTAC parses these unencrypted frames to diagnose why secure sessions failed.
                      </p>
                    </div>

                    {/* Summary Warning Cards if alerts exist */}
                    {(() => {
                      const alerts = analysisResult.tlsAlerts || [];
                      if (alerts.length === 0) return null;

                      return (
                        <div className="flex flex-col gap-4">
                          <h4 className="text-xs font-bold text-slate-400 font-mono uppercase tracking-wider">
                            🚨 High-Severity TLS Fatal Connection Failures
                          </h4>
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                            {alerts.map((alert, idx) => {
                              let plainEnglishReason = "Unmapped TLS/SSL Connection Error.";
                              let firewallNote = "Connection aborted during secure tunnel negotiation.";
                              
                              if (alert.alertCode === 40) {
                                plainEnglishReason = "Firewall Decryption Block / Cipher Mismatch";
                                firewallNote = "The local firewall or proxy intercepted the secure negotiation and found no mutually supported cipher suite, or explicitly tore down the session during handshake.";
                              } else if (alert.alertCode === 48) {
                                plainEnglishReason = "Untrusted Certificate Authority (Unknown CA)";
                                firewallNote = "The client rejected the connection because the server's SSL certificate was self-signed or signed by an untrusted proxy/decryption engine.";
                              } else if (alert.alertCode === 49) {
                                plainEnglishReason = "Access Denied / Outbound Security Policy Block";
                                firewallNote = "The connection was explicitly dropped by an inline security gateway/firewall or the server itself refused the client certificate.";
                              } else if (alert.alertCode === 70) {
                                plainEnglishReason = "Legacy TLS 1.0 Rejected (Protocol Unsupported)";
                                firewallNote = "The client attempted negotiation using a deprecated TLS 1.0 or TLS 1.1 protocol version which is disabled or prohibited by security standard policies.";
                              }

                              return (
                                <div key={idx} className="bg-purple-950/15 border border-purple-500/20 rounded-xl p-5 flex flex-col gap-3 relative overflow-hidden">
                                  {/* Optical background glow effect */}
                                  <div className="absolute top-0 right-0 w-24 h-24 bg-purple-500/5 rounded-full blur-2xl"></div>
                                  
                                  <div className="flex items-center justify-between border-b border-purple-950/40 pb-2">
                                    <span className="text-[10px] font-mono font-bold text-purple-400 uppercase tracking-widest">
                                      TLS ALERT CODE {alert.alertCode}
                                    </span>
                                    <span className="text-[10px] text-slate-500 font-mono tabular-nums">
                                      Offset: {new Date(alert.timestamp).toISOString().split('T')[1].slice(0, -1)}s
                                    </span>
                                  </div>

                                  <div className="flex flex-col gap-1">
                                    <span className="text-xs text-slate-400 font-sans">Attempted Server (SNI):</span>
                                    <span className="text-sm font-bold font-mono text-cyan-300 select-all">{alert.sni}</span>
                                  </div>

                                  <div className="flex flex-col gap-1">
                                    <span className="text-xs text-slate-400 font-sans">Failure Verdict:</span>
                                    <span className="text-sm font-bold text-purple-300 font-sans">{plainEnglishReason}</span>
                                  </div>

                                  <p className="text-[11px] text-slate-400 leading-relaxed font-sans mt-1 bg-purple-950/30 p-2.5 rounded border border-purple-950/50">
                                    <strong>Forensic Explanation:</strong> {alert.explanation}
                                    <br />
                                    <strong className="text-slate-300 block mt-1.5">Firewall Action Note:</strong> {firewallNote}
                                  </p>
                                </div>
                              );
                            })}
                          </div>
                        </div>
                      );
                    })()}

                    {/* All TLS Sessions & Handshake Log Table */}
                    <div className="flex flex-col gap-3 mt-2">
                      <span className="text-xs font-bold text-slate-400 font-mono uppercase tracking-wider">
                        📋 Comprehensive Secure Tunnel Handshake & Alert Logs
                      </span>
                      <div className="overflow-x-auto">
                        <table className="w-full text-left text-xs border-collapse">
                          <thead>
                            <tr className="border-b border-slate-900 text-slate-500 font-medium font-mono">
                              <th className="py-2.5">Time Offset</th>
                              <th className="py-2.5">Client Host</th>
                              <th className="py-2.5"></th>
                              <th className="py-2.5">Server Host</th>
                              <th className="py-2.5">Indicated Server (SNI)</th>
                              <th className="py-2.5">Secure Transaction Code</th>
                              <th className="py-2.5">Forensic Classification</th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-slate-900 font-mono text-[11px] tabular-nums">
                            {(analysisResult.tlsAlerts || []).map((alert, idx) => (
                              <tr key={idx} className="hover:bg-slate-900/30 transition-colors text-purple-200">
                                <td className="py-3 text-slate-400">
                                  {new Date(alert.timestamp).toISOString().split('T')[1].slice(0, -1)}s
                                </td>
                                <td className="py-3 font-semibold">{alert.srcIp}:{alert.srcPort}</td>
                                <td className="py-3 text-slate-600"><ArrowRight className="h-3 w-3" /></td>
                                <td className="py-3 font-semibold">{alert.dstIp}:{alert.dstPort}</td>
                                <td className="py-3 font-bold text-cyan-300 select-all">{alert.sni}</td>
                                <td className="py-3 text-purple-400 font-bold">Alert {alert.alertCode} ({alert.alertName})</td>
                                <td className="py-3 font-sans">
                                  <span className="px-1.5 py-0.5 text-[8px] font-sans font-semibold rounded bg-purple-500/10 border border-purple-500/20 text-purple-400 uppercase animate-pulse">
                                    Secure Connection Aborted
                                  </span>
                                </td>
                              </tr>
                            ))}
                            {(!analysisResult.tlsAlerts || analysisResult.tlsAlerts.length === 0) && (
                              <tr>
                                <td colSpan={7} className="py-12 text-center text-slate-500 italic">No TLS handshakes with fatal connection alert records captured in this trace. Secure negotiation completed nominally.</td>
                              </tr>
                            )}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {/* TAB 10: INGRESS VS EGRESS CORRELATION */}
              {activeTab === 'correlation' && (
                <div className="flex flex-col gap-6">
                  {/* Header */}
                  <div className="bg-slate-900/10 border border-slate-900 rounded-xl p-5 flex flex-col gap-4">
                    <div className="flex items-center justify-between border-b border-slate-900 pb-3">
                      <div className="flex items-center gap-2">
                        <Sliders className="h-4 w-4 text-red-500 animate-pulse" />
                        <span className="text-sm font-semibold text-slate-200">
                          Dual-Capture Ingress vs. Egress Correlation (Drop Proof Engine)
                        </span>
                      </div>
                      <span className="text-[10px] font-mono text-red-400 bg-red-500/10 px-2 py-0.5 border border-red-500/25 rounded font-bold uppercase tracking-wider">
                        DropProof L4
                      </span>
                    </div>

                    <div className="bg-slate-950/40 border border-slate-900/60 p-4 rounded-lg flex flex-col gap-2">
                      <h4 className="text-xs font-semibold text-red-400 font-sans uppercase">Correlative Packet Dropping Proof Methodology</h4>
                      <p className="text-[11px] text-slate-400 leading-relaxed font-sans">
                        To definitively prove firewall packet drops (whether from security policy deny rules, flow drops, or SSL/TLS decryption failures), we compare synchronized dual-interface captures. By matching every ingress TCP segment's <strong>IP Identification (IP ID)</strong> and <strong>TCP Sequence Number</strong> against the egress interface capture, we identify segments that entered the appliance but were never forwarded.
                      </p>
                    </div>

                    {/* Dual Upload Selectors Side-By-Side */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mt-2">
                      {/* Dropzone 1: Ingress Upload */}
                      <div className="bg-slate-950/60 border border-slate-900 hover:border-slate-800 p-5 rounded-xl flex flex-col gap-4 transition-colors">
                        <div className="flex items-center justify-between">
                          <span className="text-xs font-bold text-slate-300 uppercase tracking-wide">
                            📥 Label 1: Client-to-Firewall (Ingress Capture)
                          </span>
                          {ingressResult ? (
                            <span className="text-[10px] font-mono font-semibold text-emerald-400 font-sans">Loaded ({ingressResult.totalPackets} pkts)</span>
                          ) : (
                            <span className="text-[10px] font-mono font-semibold text-slate-500 font-sans">Awaiting File...</span>
                          )}
                        </div>

                        <div className="flex flex-col gap-2">
                          <input
                            type="file"
                            id="ingress-upload"
                            accept=".pcap,.pcapng"
                            onChange={async (e) => {
                              const file = e.target.files?.[0];
                              if (!file) return;
                              setIngressFileName(file.name);
                              setIsCorrelating(true);
                              try {
                                const data = await parsePcapFile(file);
                                setIngressResult(data);
                              } catch (err: any) {
                                alert(`Failed to parse Ingress capture: ${err.message}`);
                              } finally {
                                setIsCorrelating(false);
                              }
                            }}
                            className="hidden"
                          />
                          <label
                            htmlFor="ingress-upload"
                            className="flex flex-col items-center justify-center p-6 border border-dashed border-slate-800 hover:border-slate-700 bg-slate-950 hover:bg-slate-900/40 rounded-lg cursor-pointer transition-all"
                          >
                            <Upload className="h-6 w-6 text-slate-500 mb-2" />
                            <span className="text-xs font-semibold text-slate-300 font-sans">
                              {ingressFileName ? ingressFileName : "Upload Ingress PCAP / PCAPNG"}
                            </span>
                            <span className="text-[10px] text-slate-500 mt-1 font-sans">Accepts standard binary captures</span>
                          </label>
                        </div>
                      </div>

                      {/* Dropzone 2: Egress Upload */}
                      <div className="bg-slate-950/60 border border-slate-900 hover:border-slate-800 p-5 rounded-xl flex flex-col gap-4 transition-colors">
                        <div className="flex items-center justify-between">
                          <span className="text-xs font-bold text-slate-300 uppercase tracking-wide">
                            📤 Label 2: Firewall-to-Server (Egress Capture)
                          </span>
                          {egressResult ? (
                            <span className="text-[10px] font-mono font-semibold text-emerald-400 font-sans">Loaded ({egressResult.totalPackets} pkts)</span>
                          ) : (
                            <span className="text-[10px] font-mono font-semibold text-slate-500 font-sans">Awaiting File...</span>
                          )}
                        </div>

                        <div className="flex flex-col gap-2">
                          <input
                            type="file"
                            id="egress-upload"
                            accept=".pcap,.pcapng"
                            onChange={async (e) => {
                              const file = e.target.files?.[0];
                              if (!file) return;
                              setEgressFileName(file.name);
                              setIsCorrelating(true);
                              try {
                                const data = await parsePcapFile(file);
                                setEgressResult(data);
                              } catch (err: any) {
                                alert(`Failed to parse Egress capture: ${err.message}`);
                              } finally {
                                setIsCorrelating(false);
                              }
                            }}
                            className="hidden"
                          />
                          <label
                            htmlFor="egress-upload"
                            className="flex flex-col items-center justify-center p-6 border border-dashed border-slate-800 hover:border-slate-700 bg-slate-950 hover:bg-slate-900/40 rounded-lg cursor-pointer transition-all"
                          >
                            <Upload className="h-6 w-6 text-slate-500 mb-2" />
                            <span className="text-xs font-semibold text-slate-300 font-sans">
                              {egressFileName ? egressFileName : "Upload Egress PCAP / PCAPNG"}
                            </span>
                            <span className="text-[10px] text-slate-500 mt-1 font-sans">Accepts standard binary captures</span>
                          </label>
                        </div>
                      </div>
                    </div>

                    {/* Action Run Correlation Button */}
                    <div className="flex justify-center mt-2">
                      <button
                        type="button"
                        disabled={!ingressResult || !egressResult || isCorrelating}
                        onClick={() => {
                          if (!ingressResult || !egressResult) return;
                          setIsCorrelating(true);
                          setTimeout(() => {
                            // Run the O(N) correlation function
                            const egressPackets = egressResult.packets || [];
                            const egressKeys = new Set<string>();
                            egressPackets.forEach(p => {
                              if (p.ipId !== undefined && p.tcpSeq !== undefined) {
                                egressKeys.add(`${p.ipId}_${p.tcpSeq}`);
                              }
                            });

                            const ingressPackets = ingressResult.packets || [];
                            const drops: Array<{
                              ipId: number;
                              tcpSeq: number;
                              ingressTime: number;
                              srcIp: string;
                              dstIp: string;
                              srcPort?: number;
                              dstPort?: number;
                              length: number;
                              verdict: string;
                            }> = [];

                            ingressPackets.forEach(p => {
                              const isTcp = p.protocol === 'TCP' || p.protocol === 'HTTP' || p.protocol === 'FTP';
                              if (isTcp && p.ipId !== undefined && p.tcpSeq !== undefined) {
                                const key = `${p.ipId}_${p.tcpSeq}`;
                                if (!egressKeys.has(key)) {
                                  drops.push({
                                    ipId: p.ipId,
                                    tcpSeq: p.tcpSeq,
                                    ingressTime: p.timestamp,
                                    srcIp: p.srcIp,
                                    dstIp: p.dstIp,
                                    srcPort: p.srcPort,
                                    dstPort: p.dstPort,
                                    length: p.length,
                                    verdict: "Confirmed dropped inside the appliance (Policy Deny, Flow Drop, or Decryption Failure)"
                                  });
                                }
                              }
                            });

                            setCorrelationTable(drops);
                            setIsCorrelating(false);
                          }, 600);
                        }}
                        className="px-6 py-2.5 bg-red-600 hover:bg-red-500 disabled:bg-slate-900 text-slate-100 disabled:text-slate-500 font-bold rounded-lg text-xs tracking-wider uppercase transition-colors shrink-0 flex items-center gap-2 cursor-pointer disabled:cursor-not-allowed border border-red-500/20 disabled:border-slate-850 font-sans shadow-sm"
                      >
                        <RefreshCw className={`h-4 w-4 ${isCorrelating ? 'animate-spin' : ''}`} />
                        <span>Run Drop Proof Ingress vs. Egress Correlation</span>
                      </button>
                    </div>

                    {/* Drop Proof Alert Table */}
                    <div className="flex flex-col gap-3 mt-4">
                      <div className="flex items-center justify-between border-b border-slate-900 pb-2">
                        <span className="text-xs font-bold text-red-400 font-mono uppercase tracking-wider">
                          🚨 Verified Appliance Dropped Packet Proofs (Ingress/Egress Discrepancies)
                        </span>
                        {correlationTable.length > 0 && (
                          <span className="text-[10px] font-mono font-bold text-red-400 bg-red-500/10 px-2 py-0.5 border border-red-500/20 rounded animate-pulse">
                            {correlationTable.length} Packet Drops Confirmed
                          </span>
                        )}
                      </div>

                      <div className="overflow-x-auto">
                        <table className="w-full text-left text-xs border-collapse">
                          <thead>
                            <tr className="border-b border-slate-900 text-slate-500 font-medium font-mono">
                              <th className="py-2.5">Ingress Packet Index</th>
                              <th className="py-2.5">Ingress Time Offset</th>
                              <th className="py-2.5">Source Connection</th>
                              <th className="py-2.5">Destination Connection</th>
                              <th className="py-2.5 text-right font-mono">IP ID</th>
                              <th className="py-2.5 text-right font-mono">TCP Seq</th>
                              <th className="py-2.5 text-right font-mono">Frame Size</th>
                              <th className="py-2.5 pl-6">Definitive Forensic Verdict</th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-slate-900 font-mono text-[11px] tabular-nums">
                            {correlationTable.map((row, i) => (
                              <tr key={i} className="hover:bg-red-500/5 transition-colors text-red-200">
                                <td className="py-3 text-slate-400">
                                  #{i + 1}
                                </td>
                                <td className="py-3 text-slate-400">
                                  {new Date(row.ingressTime).toISOString().split('T')[1].slice(0, -1)}s
                                </td>
                                <td className="py-3 font-semibold">{row.srcIp}:{row.srcPort}</td>
                                <td className="py-3 font-semibold">{row.dstIp}:{row.dstPort}</td>
                                <td className="py-3 text-right text-slate-300">0x{row.ipId.toString(16).toUpperCase()} ({row.ipId})</td>
                                <td className="py-3 text-right text-slate-300 font-bold">{row.tcpSeq}</td>
                                <td className="py-3 text-right text-slate-400">{row.length} B</td>
                                <td className="py-3 pl-6 font-sans text-xs font-bold text-red-400">
                                  {row.verdict}
                                </td>
                              </tr>
                            ))}
                            {correlationTable.length === 0 && (
                              <tr>
                                <td colSpan={8} className="py-12 text-center text-slate-500 italic font-sans text-xs">
                                  {!ingressResult || !egressResult ? (
                                    "Awaiting file ingestion and Drop Proof calculation. Load both Ingress and Egress files to begin correlation."
                                  ) : (
                                    "No packets dropped! 100% correlation. All ingress segments were successfully matched and forwarded to the egress interface."
                                  )}
                                </td>
                              </tr>
                            )}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {/* TAB 11: ASYMMETRIC ROUTING & STATEFUL DROP ANALYZER */}
              {activeTab === 'asymmetric' && (
                <div className="flex flex-col gap-6">
                  {/* Warning Dashboard Header */}
                  <div className="bg-amber-500/5 border border-amber-500/20 rounded-xl p-6 flex flex-col gap-4">
                    <div className="flex items-center justify-between border-b border-amber-500/15 pb-4">
                      <div className="flex items-center gap-3">
                        <AlertTriangle className="h-5 w-5 text-amber-500 animate-pulse" />
                        <h3 className="text-sm font-semibold text-white">
                          Stateful Firewall Bypass Detected
                        </h3>
                      </div>
                      <span className="text-[10px] font-mono font-bold text-amber-400 bg-amber-500/10 px-2 py-0.5 border border-amber-500/25 rounded uppercase tracking-wider animate-pulse">
                        Asymmetry Alert
                      </span>
                    </div>

                    <div className="flex flex-col gap-2">
                      <h4 className="text-xs font-semibold text-amber-400 font-sans uppercase">Asymmetric Routing & Stateful Packet Drop Theory</h4>
                      <p className="text-[11px] text-slate-400 leading-relaxed font-sans">
                        Stateful firewalls track the exact TCP 3-way handshake state (SYN &rarr; SYN-ACK &rarr; ACK). If return packets take an alternate path (asymmetric routing) and bypass the firewall, or if client packets arrive out-of-sequence/without a handshake, the firewall has no matching session table entry. Consequently, it drops these "orphaned" packets as invalid state bypasses.
                      </p>
                    </div>
                  </div>

                  {/* Summary Metric Cards */}
                  {(() => {
                    const anomalies = analysisResult.asymmetricRouteAnomalies || [];
                    const orphanedAcks = anomalies.filter(a => a.firstFlagObserved.includes('ACK')).length;
                    const ttlShifts = anomalies.filter(a => a.firstFlagObserved === 'TTL Shift').length;
                    const icmpRedirects = anomalies.filter(a => a.firstFlagObserved === 'ICMP Redirect').length;

                    return (
                      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                        <div className="bg-slate-950 p-4 rounded-xl border border-slate-900 flex flex-col gap-1.5">
                          <span className="text-[10px] text-slate-500 font-bold uppercase tracking-wider">Total Anomalies</span>
                          <span className="text-xl font-bold font-mono text-slate-100 tabular-nums">{anomalies.length}</span>
                        </div>
                        <div className="bg-slate-950 p-4 rounded-xl border border-slate-900 flex flex-col gap-1.5">
                          <span className="text-[10px] text-amber-400 font-bold uppercase tracking-wider">Orphaned TCP Flags</span>
                          <span className="text-xl font-bold font-mono text-amber-400 tabular-nums">{orphanedAcks}</span>
                        </div>
                        <div className="bg-slate-950 p-4 rounded-xl border border-slate-900 flex flex-col gap-1.5">
                          <span className="text-[10px] text-cyan-400 font-bold uppercase tracking-wider">TTL Path Shifts</span>
                          <span className="text-xl font-bold font-mono text-cyan-400 tabular-nums">{ttlShifts}</span>
                        </div>
                        <div className="bg-slate-950 p-4 rounded-xl border border-slate-900 flex flex-col gap-1.5">
                          <span className="text-[10px] text-purple-400 font-bold uppercase tracking-wider">ICMP Redirects</span>
                          <span className="text-xl font-bold font-mono text-purple-400 tabular-nums">{icmpRedirects}</span>
                        </div>
                      </div>
                    );
                  })()}

                  {/* Data Table */}
                  <div className="bg-slate-900/10 border border-slate-900 rounded-xl p-5 flex flex-col gap-4">
                    <span className="text-xs font-bold text-slate-400 font-mono uppercase tracking-wider">
                      📋 Stateful Firewall Bypass Flow Logs
                    </span>

                    <div className="overflow-x-auto">
                      <table className="w-full text-left text-xs border-collapse">
                        <thead>
                          <tr className="border-b border-slate-900 text-slate-500 font-medium font-mono">
                            <th className="py-2.5">Time Offset</th>
                            <th className="py-2.5">Source Connection</th>
                            <th className="py-2.5"></th>
                            <th className="py-2.5">Destination Connection</th>
                            <th className="py-2.5">Flag / Event Observed</th>
                            <th className="py-2.5 font-mono text-right">TTL/IPID</th>
                            <th className="py-2.5 pl-6">Definitive Forensic Verdict</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-900 font-mono text-[11px] tabular-nums">
                          {(analysisResult.asymmetricRouteAnomalies || []).map((row, i) => {
                            const isRedirect = row.firstFlagObserved === 'ICMP Redirect';
                            const isTtlShift = row.firstFlagObserved === 'TTL Shift';
                            let rowColor = 'text-amber-200';
                            if (isRedirect) rowColor = 'text-purple-200';
                            if (isTtlShift) rowColor = 'text-cyan-200';

                            return (
                              <tr key={i} className={`hover:bg-amber-500/5 transition-colors ${rowColor}`}>
                                <td className="py-3 text-slate-400">
                                  {new Date(row.timestamp).toISOString().split('T')[1].slice(0, -1)}s
                                </td>
                                <td className="py-3 font-semibold">
                                  {row.srcIp}{row.srcPort ? `:${row.srcPort}` : ''}
                                </td>
                                <td className="py-3 text-slate-600">
                                  <ArrowRight className="h-3 w-3" />
                                </td>
                                <td className="py-3 font-semibold">
                                  {row.dstIp}{row.dstPort ? `:${row.dstPort}` : ''}
                                </td>
                                <td className="py-3 font-bold">
                                  {row.firstFlagObserved}
                                </td>
                                <td className="py-3 text-right text-slate-400">
                                  {row.ttlValue !== undefined ? `TTL: ${row.ttlValue}` : ''}
                                  {row.ipId !== undefined ? ` · IPID: 0x${row.ipId.toString(16).toUpperCase()}` : ''}
                                </td>
                                <td className="py-3 pl-6 font-sans text-xs font-bold text-amber-500">
                                  {row.verdict}
                                  <span className="block text-[9px] font-sans font-normal text-slate-400 mt-1">
                                    {row.detail}
                                  </span>
                                </td>
                              </tr>
                            );
                          })}
                          {(!analysisResult.asymmetricRouteAnomalies || analysisResult.asymmetricRouteAnomalies.length === 0) && (
                            <tr>
                              <td colSpan={7} className="py-12 text-center text-slate-500 italic font-sans text-xs">
                                No asymmetric routing anomalies or mid-stream firewall bypasses detected in the active packet stream. All TCP sessions comply with state transitions.
                              </td>
                            </tr>
                          )}
                        </tbody>
                      </table>
                    </div>
                  </div>
                </div>
              )}

              {/* TAB 12: MICROBURST BUFFER STARVATION VISUALIZER */}
              {activeTab === 'microburst' && (
                <div className="flex flex-col gap-6">
                  {/* Warning Header Panel */}
                  <div className="bg-orange-500/5 border border-orange-500/20 rounded-xl p-5 flex flex-col gap-4 relative overflow-hidden">
                    <div className="absolute top-0 right-0 w-32 h-32 bg-orange-500/5 rounded-full blur-3xl"></div>
                    <div className="flex items-center justify-between border-b border-orange-500/10 pb-3">
                      <div className="flex items-center gap-2">
                        <Activity className="h-4.5 w-4.5 text-orange-400 animate-pulse" />
                        <span className="text-xs font-semibold text-slate-200">
                          Microburst Buffer Starvation & Interface Queue Visualizer
                        </span>
                      </div>
                      <span className="text-[10px] font-mono text-orange-400 bg-orange-500/10 px-2 py-0.5 border border-orange-500/25 rounded uppercase tracking-wider animate-pulse">
                        Millisecond Resolution (1ms)
                      </span>
                    </div>

                    <div className="flex flex-col gap-2">
                      <h4 className="text-xs font-semibold text-orange-300 font-sans uppercase">The Threat of Microbursting (Hardware Queue Exhaustion)</h4>
                      <p className="text-[11px] text-slate-400 leading-relaxed font-sans">
                        Standard network monitoring (SNMP) runs on average-based polls of 1 to 5 minutes. This completely smooths out millisecond-level traffic spikes (microbursting). If an incoming traffic burst exceeds the firewall interface's physical queue memory capacity for even a single millisecond, the buffer immediately starves, and any subsequent packets are instantly dropped (tail-dropped). Standard statistics show normal 10% average utilization while physical packets are silently lost.
                      </p>
                    </div>
                  </div>

                  {/* Interactive Controls & Capacity Settings Card */}
                  <div className="bg-slate-900/10 border border-slate-900 rounded-xl p-5 flex flex-col gap-5">
                    <div className="flex items-center justify-between border-b border-slate-900 pb-3">
                      <span className="text-xs font-semibold text-slate-200">
                        Firewall Physical Interface Allocation Controls
                      </span>
                      <span className="text-[10px] font-mono text-slate-500 uppercase">SLA Adaptive Boundary</span>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-3 gap-6 items-center">
                      {/* Interface Slider */}
                      <div className="flex flex-col gap-2 md:col-span-2">
                        <div className="flex items-center justify-between">
                          <label className="text-xs font-bold text-slate-400 uppercase">
                            Firewall Interface Capacity Threshold
                          </label>
                          <span className="text-sm font-mono font-bold text-orange-400 tabular-nums bg-orange-500/5 px-2.5 py-1 border border-orange-500/15 rounded">
                            {microburstCapacity} Mbps
                          </span>
                        </div>
                        <input
                          type="range"
                          min="10"
                          max="1000"
                          step="10"
                          value={microburstCapacity}
                          onChange={(e) => setMicroburstCapacity(Number(e.target.value))}
                          className="w-full accent-orange-500 bg-slate-950 border border-slate-900 h-2 rounded-lg cursor-pointer"
                        />
                        <div className="flex justify-between text-[9px] font-mono text-slate-500">
                          <span>10 Mbps (Insecure DSL / WAN)</span>
                          <span>250 Mbps (Branch Office MPLS)</span>
                          <span>500 Mbps (Standard Gateway)</span>
                          <span>1000 Mbps (Gigabit Uplink Core)</span>
                        </div>
                      </div>

                      {/* Interactive Presets */}
                      <div className="flex flex-col gap-2">
                        <span className="text-[10px] text-slate-500 font-bold uppercase tracking-wider">
                          SLA Interface Speed Presets
                        </span>
                        <div className="grid grid-cols-2 gap-2">
                          <button
                            type="button"
                            onClick={() => setMicroburstCapacity(50)}
                            className="py-1.5 px-2 bg-slate-950 hover:bg-slate-900 border border-slate-900 hover:border-slate-800 text-[10px] font-semibold font-mono text-cyan-400 rounded transition-colors cursor-pointer"
                          >
                            50 Mbps (T1/E1 WAN)
                          </button>
                          <button
                            type="button"
                            onClick={() => setMicroburstCapacity(150)}
                            className="py-1.5 px-2 bg-slate-950 hover:bg-slate-900 border border-slate-900 hover:border-slate-800 text-[10px] font-semibold font-mono text-cyan-400 rounded transition-colors cursor-pointer"
                          >
                            150 Mbps (Fibre Branch)
                          </button>
                          <button
                            type="button"
                            onClick={() => setMicroburstCapacity(300)}
                            className="py-1.5 px-2 bg-slate-950 hover:bg-slate-900 border border-slate-900 hover:border-slate-800 text-[10px] font-semibold font-mono text-cyan-400 rounded transition-colors cursor-pointer"
                          >
                            300 Mbps (ISP Gateway)
                          </button>
                          <button
                            type="button"
                            onClick={() => setMicroburstCapacity(1000)}
                            className="py-1.5 px-2 bg-slate-950 hover:bg-slate-900 border border-slate-900 hover:border-slate-800 text-[10px] font-semibold font-mono text-cyan-400 rounded transition-colors cursor-pointer"
                          >
                            1000 Mbps (Core 1G)
                          </button>
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Microburst Chart and Tooltip container */}
                  {(() => {
                    const packets = analysisResult?.packets || [];
                    if (packets.length === 0) return null;

                    const timestamps = packets.map(p => p.timestamp);
                    const minTime = Math.min(...timestamps);
                    const maxTime = Math.max(...timestamps);
                    const totalDurationMs = Math.ceil(maxTime - minTime) || 1;

                    // Compute 1ms binned Mbps rates
                    const bins = Array.from({ length: totalDurationMs }).map((_, idx) => {
                      const binStart = minTime + idx;
                      const binEnd = binStart + 1;
                      const binPackets = packets.filter(p => p.timestamp >= binStart && p.timestamp < binEnd);
                      const bytes = binPackets.reduce((sum, p) => sum + p.length, 0);
                      const mbps = (bytes * 8) / 1000; // bps to Mbps
                      return {
                        msOffset: idx,
                        timeSec: (idx / 1000).toFixed(3),
                        bytes,
                        packetCount: binPackets.length,
                        mbps
                      };
                    });

                    const overflowBins = bins.filter(b => b.mbps > microburstCapacity);
                    const maxMbps = Math.max(...bins.map(b => b.mbps)) || 1;
                    const chartHeight = 240;
                    const chartWidth = Math.max(800, bins.length * 6); // responsive scrolling width

                    return (
                      <div className="flex flex-col gap-6">
                        {/* Summary Metrics */}
                        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                          <div className="bg-slate-950 p-4 rounded-xl border border-slate-900 flex flex-col gap-1">
                            <span className="text-[10px] text-slate-500 font-bold uppercase tracking-wider">Max Instantaneous Bursts</span>
                            <span className="text-xl font-bold font-mono text-slate-100 tabular-nums">
                              {maxMbps.toFixed(2)} Mbps
                            </span>
                          </div>
                          <div className="bg-slate-950 p-4 rounded-xl border border-slate-900 flex flex-col gap-1">
                            <span className="text-[10px] text-red-400 font-bold uppercase tracking-wider">Queue Overflows / Drops</span>
                            <span className="text-xl font-bold font-mono text-red-400 tabular-nums">
                              {overflowBins.length} ms-intervals
                            </span>
                          </div>
                          <div className="bg-slate-950 p-4 rounded-xl border border-slate-900 flex flex-col gap-1">
                            <span className="text-[10px] text-emerald-400 font-bold uppercase tracking-wider">Queue Health Rate</span>
                            <span className="text-xl font-bold font-mono text-emerald-400 tabular-nums">
                              {((1 - (overflowBins.length / bins.length)) * 100).toFixed(2)}% healthy
                            </span>
                          </div>
                        </div>

                        {/* Chart Area wrapper with scrollbar */}
                        <div className="bg-slate-900/10 border border-slate-900 rounded-xl p-5 flex flex-col gap-4">
                          <div className="flex items-center justify-between">
                            <span className="text-xs font-semibold text-slate-200">
                              📈 Real-Time 1-Millisecond Instantaneous Throughput (Mbps)
                            </span>
                            <div className="flex items-center gap-4 text-[10px] font-mono text-slate-500">
                              <div className="flex items-center gap-1.5">
                                <span className="w-2.5 h-2.5 bg-cyan-500/40 rounded-sm"></span>
                                <span>Nominal</span>
                              </div>
                              <div className="flex items-center gap-1.5">
                                <span className="w-2.5 h-2.5 bg-red-500 rounded-sm animate-pulse"></span>
                                <span>Buffer Overflow</span>
                              </div>
                              <span className="bg-slate-950 border border-slate-850 px-2 py-0.5 rounded text-slate-400 uppercase tracking-widest font-bold font-mono">
                                Scroll Horizontally To Inspect
                              </span>
                            </div>
                          </div>

                          <div className="overflow-x-auto border border-slate-950 rounded-xl bg-slate-950 p-4 relative scrollbar-thin scrollbar-thumb-slate-800 scrollbar-track-transparent">
                            <div style={{ width: `${chartWidth}px` }} className="relative h-[280px]">
                              {/* Overlay Interactive SVG Chart */}
                              <svg width={chartWidth} height={chartHeight + 40} className="font-mono text-[9px] overflow-visible">
                                <g transform="translate(0, 10)">
                                  {/* Grid Lines (Horizontal values in Mbps) */}
                                  {Array.from({ length: 5 }).map((_, stepIdx) => {
                                    const yVal = (chartHeight / 4) * stepIdx;
                                    const mbpsVal = maxMbps - (maxMbps / 4) * stepIdx;
                                    return (
                                      <g key={stepIdx} transform={`translate(0, ${yVal})`}>
                                        <line x1="0" y1="0" x2={chartWidth} y2="0" stroke="#0f172a" strokeWidth="1" />
                                        <text x="5" y="-5" fill="#475569" className="font-bold tabular-nums">
                                          {mbpsVal.toFixed(1)} Mbps
                                        </text>
                                      </g>
                                    );
                                  })}

                                  {/* Render each millisecond bin as a sleek bar */}
                                  {bins.map((bin, idx) => {
                                    const barWidth = 4;
                                    const barGap = 2;
                                    const x = idx * (barWidth + barGap) + 50;
                                    const valRatio = bin.mbps / maxMbps;
                                    const calculatedHeight = Math.max(1, valRatio * chartHeight);
                                    const y = chartHeight - calculatedHeight;
                                    const isOverflow = bin.mbps > microburstCapacity;

                                    return (
                                      <g key={bin.msOffset} className="group cursor-pointer">
                                        {/* Hover state vertical highlight */}
                                        <rect
                                          x={x - 1}
                                          y="0"
                                          width={barWidth + 2}
                                          height={chartHeight}
                                          fill="rgba(255,255,255,0.03)"
                                          className="opacity-0 group-hover:opacity-100 transition-opacity"
                                        />

                                        {/* The bar itself */}
                                        <rect
                                          x={x}
                                          y={y}
                                          width={barWidth}
                                          height={calculatedHeight}
                                          fill={isOverflow ? "#ef4444" : "rgba(6, 182, 212, 0.5)"}
                                          stroke={isOverflow ? "#f87171" : "#06b6d4"}
                                          strokeWidth={0.5}
                                          className="transition-all duration-300"
                                        />

                                        {/* Hover Tooltip Popup (rendered conditionally near the bar inside group for zero latency) */}
                                        <g className="opacity-0 group-hover:opacity-100 pointer-events-none transition-opacity duration-150 z-50">
                                          <rect
                                            x={x > chartWidth - 160 ? x - 150 : x + 8}
                                            y={Math.min(chartHeight - 110, y)}
                                            width="145"
                                            height="100"
                                            rx="6"
                                            fill="#020617"
                                            stroke={isOverflow ? "#ef4444" : "#06b6d4"}
                                            strokeWidth="1.5"
                                            className="shadow-xl"
                                          />
                                          <text x={(x > chartWidth - 160 ? x - 150 : x + 8) + 10} y={Math.min(chartHeight - 110, y) + 20} fill="#f1f5f9" className="font-bold text-[10px]">
                                            Interval Offset: {bin.timeSec}s
                                          </text>
                                          <text x={(x > chartWidth - 160 ? x - 150 : x + 8) + 10} y={Math.min(chartHeight - 110, y) + 38} fill="#94a3b8">
                                            Packets: {bin.packetCount}
                                          </text>
                                          <text x={(x > chartWidth - 160 ? x - 150 : x + 8) + 10} y={Math.min(chartHeight - 110, y) + 54} fill="#94a3b8">
                                            Bytes Recv: {bin.bytes.toLocaleString()} B
                                          </text>
                                          <text x={(x > chartWidth - 160 ? x - 150 : x + 8) + 10} y={Math.min(chartHeight - 110, y) + 72} fill={isOverflow ? "#ef4444" : "#22c55e"} className="font-bold font-mono">
                                            Rate: {bin.mbps.toFixed(2)} Mbps
                                          </text>
                                          {isOverflow && (
                                            <text x={(x > chartWidth - 160 ? x - 150 : x + 8) + 10} y={Math.min(chartHeight - 110, y) + 88} fill="#ef4444" className="font-bold uppercase tracking-wider text-[8px] animate-pulse">
                                              ⚠ QUEUE OVERFLOW DROP!
                                            </text>
                                          )}
                                        </g>

                                        {/* Bottom X-Axis Timeline Labels */}
                                        {idx % 100 === 0 && (
                                          <g transform={`translate(${x}, ${chartHeight + 18})`}>
                                            <line x1="0" y1="-18" x2="0" y2="-12" stroke="#475569" strokeWidth="1" />
                                            <text x="-15" y="0" fill="#64748b" className="font-bold">
                                              {bin.timeSec}s
                                            </text>
                                          </g>
                                        )}
                                      </g>
                                    );
                                  })}

                                  {/* Overlay user-adjustable capacity threshold line */}
                                  {(() => {
                                    const thresholdY = chartHeight - (microburstCapacity / maxMbps) * chartHeight;
                                    if (thresholdY < 0 || thresholdY > chartHeight) return null;

                                    return (
                                      <g transform={`translate(0, ${thresholdY})`} className="pointer-events-none">
                                        <line
                                          x1="0"
                                          y1="0"
                                          x2={chartWidth}
                                          y2="0"
                                          stroke="#ef4444"
                                          strokeWidth="1.5"
                                          strokeDasharray="4,4"
                                        />
                                        {/* Dark backing block for threshold badge text */}
                                        <rect
                                          x="40"
                                          y="-15"
                                          width="340"
                                          height="14"
                                          fill="#ef4444"
                                          rx="2"
                                        />
                                        <text
                                          x="45"
                                          y="-5"
                                          fill="#ffffff"
                                          className="font-bold uppercase tracking-wider text-[8px]"
                                        >
                                          ⚠ Firewall Interface Capacity Threshold: {microburstCapacity} Mbps (Buffer Overflow / Hardware Queue Drop Zone)
                                        </text>
                                      </g>
                                    );
                                  })()}
                                </g>
                              </svg>
                            </div>
                          </div>
                        </div>

                        {/* Top 20 Burst Intervals Details Grid */}
                        <div className="bg-slate-900/10 border border-slate-900 rounded-xl p-5 flex flex-col gap-4">
                          <span className="text-xs font-bold text-slate-400 font-mono uppercase tracking-wider">
                            📋 Top Worst 20 Microburst Intervals Queue Diagnostics
                          </span>

                          <div className="overflow-x-auto">
                            <table className="w-full text-left text-xs border-collapse">
                              <thead>
                                <tr className="border-b border-slate-900 text-slate-500 font-medium font-mono">
                                  <th className="py-2.5">Rank</th>
                                  <th className="py-2.5">Time Offset (Sec)</th>
                                  <th className="py-2.5 text-right font-mono">Packet Count</th>
                                  <th className="py-2.5 text-right font-mono">Bytes Recv</th>
                                  <th className="py-2.5 text-right font-mono">Instantaneous Throughput</th>
                                  <th className="py-2.5 pl-8">Stateful Buffer Queue Verdict</th>
                                </tr>
                              </thead>
                              <tbody className="divide-y divide-slate-900 font-mono text-[11px] tabular-nums">
                                {bins
                                  .sort((a, b) => b.mbps - a.mbps)
                                  .slice(0, 20)
                                  .map((bin, i) => {
                                    const isOverflow = bin.mbps > microburstCapacity;
                                    return (
                                      <tr key={i} className={`hover:bg-slate-900/30 transition-colors ${isOverflow ? 'text-red-200' : 'text-slate-300'}`}>
                                        <td className="py-2.5 text-slate-500">#{i + 1}</td>
                                        <td className="py-2.5 font-bold">{bin.timeSec}s ({bin.msOffset} ms)</td>
                                        <td className="py-2.5 text-right text-slate-400">{bin.packetCount} pkts</td>
                                        <td className="py-2.5 text-right text-slate-400">{bin.bytes.toLocaleString()} B</td>
                                        <td className={`py-2.5 text-right font-bold ${isOverflow ? 'text-red-400' : 'text-cyan-400'}`}>
                                          {bin.mbps.toFixed(2)} Mbps
                                        </td>
                                        <td className="py-2.5 pl-8 font-sans">
                                          {isOverflow ? (
                                            <div className="flex flex-col">
                                              <span className="text-red-400 font-bold uppercase text-[10px]">
                                                ⚠ QUEUE OVERFLOW DETECTED
                                              </span>
                                              <span className="text-[9px] text-slate-500 leading-tight mt-0.5">
                                                Hardware packet drop confirmed due to tail-drop buffering limit. Physical interface starved.
                                              </span>
                                            </div>
                                          ) : (
                                            <div className="flex flex-col">
                                              <span className="text-emerald-400 font-bold uppercase text-[10px]">
                                                ✓ NOMINAL QUEUE STATE
                                              </span>
                                              <span className="text-[9px] text-slate-500 leading-tight mt-0.5">
                                                Physical hardware buffers absorbed packet burst successfully without starvation.
                                              </span>
                                            </div>
                                          )}
                                        </td>
                                      </tr>
                                    );
                                  })}
                              </tbody>
                            </table>
                          </div>
                        </div>
                      </div>
                    );
                  })()}
                </div>
              )}

              {/* TAB 14: ZERO-TRUST IDENTITY & RADIUS DECODER */}
              {activeTab === 'radius' && (
                <div className="flex flex-col gap-6">
                  {/* Warning Header Panel */}
                  <div className="bg-yellow-500/5 border border-yellow-500/20 rounded-xl p-5 flex flex-col gap-4 relative overflow-hidden">
                    <div className="absolute top-0 right-0 w-32 h-32 bg-yellow-500/5 rounded-full blur-3xl"></div>
                    <div className="flex items-center justify-between border-b border-yellow-500/10 pb-3">
                      <div className="flex items-center gap-2">
                        <Key className="h-4.5 w-4.5 text-yellow-400 animate-pulse" />
                        <span className="text-xs font-semibold text-slate-200">
                          Zero-Trust Identity & RADIUS Authentication Decoder
                        </span>
                      </div>
                      <span className="text-[10px] font-mono text-yellow-400 bg-yellow-500/10 px-2 py-0.5 border border-yellow-500/25 rounded uppercase tracking-wider">
                        Network Access Control (NAC) Decryptor
                      </span>
                    </div>

                    <div className="flex flex-col gap-2">
                      <h4 className="text-xs font-semibold text-yellow-300 font-sans uppercase">Identity-Based Access Monitoring (Zero-Trust RADIUS)</h4>
                      <p className="text-[11px] text-slate-400 leading-relaxed font-sans">
                        RADIUS (Remote Authentication Dial-In User Service) provides centralized AAA (Authentication, Authorization, and Accounting) management for users and devices connecting to enterprise switches, VPNs, or firewalls. By sniffing UDP ports 1812 and 1813, AutoTAC parses standard access sequences. Rejection events (Access-Reject) contain the exact denied Username/MAC address and the explicit IAM authentication server response reasons.
                      </p>
                    </div>
                  </div>

                  {/* Summary Metric Cards */}
                  {(() => {
                    const rejects = analysisResult.radiusRejects || [];
                    const distinctUsers = new Set(rejects.map(r => r.userName)).size;
                    const distinctIamServers = new Set(rejects.map(r => r.respondingIamIp)).size;

                    return (
                      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                        <div className="bg-slate-950 p-4 rounded-xl border border-slate-900 flex flex-col gap-1.5">
                          <span className="text-[10px] text-slate-500 font-bold uppercase tracking-wider">Total Access Rejections</span>
                          <span className="text-xl font-bold font-mono text-red-400 tabular-nums">{rejects.length} events</span>
                        </div>
                        <div className="bg-slate-950 p-4 rounded-xl border border-slate-900 flex flex-col gap-1.5">
                          <span className="text-[10px] text-yellow-400 font-bold uppercase tracking-wider">Distinct Blocked Identities</span>
                          <span className="text-xl font-bold font-mono text-yellow-400 tabular-nums">{distinctUsers} users / MACs</span>
                        </div>
                        <div className="bg-slate-950 p-4 rounded-xl border border-slate-900 flex flex-col gap-1.5">
                          <span className="text-[10px] text-cyan-400 font-bold uppercase tracking-wider">Active IAM Servers Reporting</span>
                          <span className="text-xl font-bold font-mono text-cyan-400 tabular-nums">{distinctIamServers} server hosts</span>
                        </div>
                      </div>
                    );
                  })()}

                  {/* Data Table */}
                  <div className="bg-slate-900/10 border border-slate-900 rounded-xl p-5 flex flex-col gap-4">
                    <span className="text-xs font-bold text-slate-400 font-mono uppercase tracking-wider">
                      📋 RADIUS Access Reject Timeline Log
                    </span>

                    <div className="overflow-x-auto">
                      <table className="w-full text-left text-xs border-collapse">
                        <thead>
                          <tr className="border-b border-slate-900 text-slate-500 font-medium font-mono">
                            <th className="py-2.5">Time Offset</th>
                            <th className="py-2.5">Target Username / MAC</th>
                            <th className="py-2.5">NAS Port Gateway (IP)</th>
                            <th className="py-2.5">Responding IAM Host (RADIUS)</th>
                            <th className="py-2.5 pl-6">Explicit Authentication Reject Reason</th>
                            <th className="py-2.5 text-center">Threat Status</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-900 font-mono text-[11px] tabular-nums">
                          {(analysisResult.radiusRejects || []).map((row, i) => (
                            <tr key={i} className="hover:bg-red-500/5 transition-colors text-red-200">
                              <td className="py-3 text-slate-400">
                                {new Date(row.timestamp).toISOString().split('T')[1].slice(0, -1)}s
                              </td>
                              <td className="py-3 font-bold text-white select-all">
                                {row.userName}
                              </td>
                              <td className="py-3 text-slate-300">
                                {row.nasIp}:{row.nasPort || '1812'}
                              </td>
                              <td className="py-3 text-slate-400">
                                {row.respondingIamIp}
                              </td>
                              <td className="py-3 pl-6 font-sans text-xs font-bold text-red-400">
                                {row.replyMessage}
                                {row.eapMessage && (
                                  <span className="block text-[9px] font-sans font-normal text-slate-500 mt-1 uppercase tracking-widest font-semibold">
                                    🔑 Active EAP tunnel encapsulation present
                                  </span>
                                )}
                              </td>
                              <td className="py-3 text-center">
                                <span className="px-1.5 py-0.5 text-[8px] font-sans font-semibold rounded bg-red-500/10 border border-red-500/20 text-red-400 uppercase animate-pulse">
                                  Access Rejected
                                </span>
                              </td>
                            </tr>
                          ))}
                          {(!analysisResult.radiusRejects || analysisResult.radiusRejects.length === 0) && (
                            <tr>
                              <td colSpan={6} className="py-12 text-center text-slate-500 italic font-sans text-xs">
                                No RADIUS Access-Reject events identified in this trace. Network access control requests are nominal.
                              </td>
                            </tr>
                          )}
                        </tbody>
                      </table>
                    </div>
                  </div>
                </div>
              )}

              {/* TAB 13: SHADOW IoT & OS FINGERPRINTING ENGINE */}
              {activeTab === 'shadow_iot' && (
                <div className="flex flex-col gap-6">
                  {/* Warning Header Panel */}
                  <div className="bg-purple-500/5 border border-purple-500/20 rounded-xl p-5 flex flex-col gap-4 relative overflow-hidden">
                    <div className="absolute top-0 right-0 w-32 h-32 bg-purple-500/5 rounded-full blur-3xl"></div>
                    <div className="flex items-center justify-between border-b border-purple-500/10 pb-3">
                      <div className="flex items-center gap-2">
                        <Cpu className="h-4.5 w-4.5 text-purple-400 animate-pulse" />
                        <span className="text-xs font-semibold text-slate-200">
                          Passive Shadow IoT Discovery & OS Fingerprinting Engine
                        </span>
                      </div>
                      <span className="text-[10px] font-mono text-purple-400 bg-purple-500/10 px-2 py-0.5 border border-purple-500/25 rounded uppercase tracking-wider animate-pulse">
                        Passive Forensic Audit (L3/L4)
                      </span>
                    </div>

                    <div className="flex flex-col gap-2">
                      <h4 className="text-xs font-semibold text-purple-300 font-sans uppercase">Heuristic-Based Passive Fingerprinting Methodology</h4>
                      <p className="text-[11px] text-slate-400 leading-relaxed font-sans">
                        To passively audit endpoints without triggering active scanning alerts, our fingerprinting engine decodes packet headers during session handshakes. By matching initial TTL values, TCP window constraints, and options arrays (such as MSS, SACK, and Window Scale availability), we can passively discover rogues (e.g. ESP32, NodeMCU, embedded RTOS) and operating systems communicating on your network interfaces.
                      </p>
                    </div>
                  </div>

                  {/* Security Alert: Rogue IoT Stacks Communicating on Protected Subnets */}
                  {(() => {
                    const rogues = (analysisResult.fingerprintedDevices || []).filter(d => d.isRogue);
                    if (rogues.length === 0) return null;

                    return (
                      <div className="flex flex-col gap-4">
                        <h4 className="text-xs font-bold text-red-400 font-mono uppercase tracking-wider">
                          🚨 CRITICAL THREAT: Rogue IoT Hardware Detected inside Protected Subnets
                        </h4>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                          {rogues.map((device, idx) => (
                            <div key={idx} className="bg-red-950/15 border border-red-500/20 rounded-xl p-5 flex flex-col gap-3 relative overflow-hidden animate-pulse">
                              <div className="absolute top-0 right-0 w-24 h-24 bg-red-500/5 rounded-full blur-2xl"></div>
                              
                              <div className="flex items-center justify-between border-b border-red-950/40 pb-2">
                                <span className="text-[10px] font-mono font-bold text-red-400 uppercase tracking-widest">
                                  ROGUE DEVICE THREAT WARNING
                                </span>
                                <span className="text-[9px] text-red-500 font-mono font-bold uppercase tracking-wider bg-red-500/10 px-2 py-0.5 rounded border border-red-500/20">
                                  {device.subnetStatus}
                                </span>
                              </div>

                              <div className="flex flex-col gap-1">
                                <span className="text-xs text-slate-400 font-sans">Host IP Address:</span>
                                <span className="text-sm font-bold font-mono text-white select-all">{device.ip}</span>
                              </div>

                              <div className="flex flex-col gap-1">
                                <span className="text-xs text-slate-400 font-sans">Fingerprinted Stack:</span>
                                <span className="text-sm font-bold text-purple-300 font-sans">{device.inferredOs}</span>
                              </div>

                              <div className="flex flex-col gap-1">
                                <span className="text-xs text-slate-400 font-sans">Security Breach Vector:</span>
                                <span className="text-[11px] text-slate-300 leading-normal font-sans font-medium">
                                  Passive audit caught an unmanaged embedded system trying to traverse protected zones. This host reached secure servers/ports: <strong className="font-mono text-cyan-300">{device.destinationsReached.join(', ')}</strong>.
                                </span>
                              </div>

                              <p className="text-[11px] text-slate-400 leading-relaxed font-sans mt-1 bg-red-950/30 p-2.5 rounded border border-red-950/50">
                                <strong>Technical Signature:</strong> Initial TTL: <strong className="text-slate-300">{device.ttl}</strong>, TCP Window: <strong className="text-slate-300">{device.windowSize} B</strong>, MSS: <strong className="text-slate-300">{device.mss || 'None'}</strong>, SACK: <strong className="text-slate-300">{device.sackPermitted ? 'Permitted' : 'Disabled'}</strong>, Window Scale: <strong className="text-slate-300">{device.windowScale !== undefined ? device.windowScale : 'None'}</strong>.
                              </p>
                            </div>
                          ))}
                        </div>
                      </div>
                    );
                  })()}

                  {/* Device Discovery Grid */}
                  <div className="bg-slate-900/10 border border-slate-900 rounded-xl p-5 flex flex-col gap-4">
                    <div className="flex items-center justify-between border-b border-slate-900 pb-3">
                      <span className="text-xs font-semibold text-slate-200">
                        🔍 PASSIVELY DISCOVERED ENDPOINTS MATRIX & OPERATING SYSTEMS
                      </span>
                      <span className="text-[10px] text-slate-500 font-mono">Sorted by Activity (Packet Vol)</span>
                    </div>

                    <div className="overflow-x-auto">
                      <table className="w-full text-left text-xs border-collapse">
                        <thead>
                          <tr className="border-b border-slate-900 text-slate-500 font-medium font-mono">
                            <th className="py-2.5">Endpoint IP</th>
                            <th className="py-2.5">Inferred System / Hardware OS</th>
                            <th className="py-2.5 text-right font-mono">TTL</th>
                            <th className="py-2.5 text-right font-mono">TCP Window</th>
                            <th className="py-2.5 text-right font-mono">MSS / Options</th>
                            <th className="py-2.5 text-right font-mono">Packet Vol</th>
                            <th className="py-2.5 pl-8">Network Zone Integrity</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-900 font-mono text-[11px] tabular-nums">
                          {(analysisResult.fingerprintedDevices || [])
                            .sort((a, b) => b.packetCount - a.packetCount)
                            .map((device, i) => {
                              const isRogue = device.isRogue;
                              let osClass = 'text-slate-300';
                              if (device.inferredOs === 'Windows') osClass = 'text-blue-400';
                              else if (device.inferredOs === 'Linux/Android') osClass = 'text-emerald-400';
                              else if (device.inferredOs.includes('IoT')) osClass = 'text-purple-400 font-bold';

                              return (
                                <tr key={i} className={`hover:bg-slate-900/30 transition-colors ${isRogue ? 'bg-red-500/5' : ''}`}>
                                  <td className="py-3 font-semibold text-white select-all">{device.ip}</td>
                                  <td className={`py-3 font-semibold ${osClass}`}>
                                    {device.inferredOs === 'Rogue Embedded IoT System (RTOS)' ? (
                                      <span className="flex items-center gap-1">
                                        <span className="w-1.5 h-1.5 bg-purple-500 rounded-full inline-block animate-pulse"></span>
                                        Rogue Embedded IoT (RTOS)
                                      </span>
                                    ) : (
                                      device.inferredOs
                                    )}
                                  </td>
                                  <td className="py-3 text-right text-slate-400">{device.ttl}</td>
                                  <td className="py-3 text-right text-slate-400">{device.windowSize.toLocaleString()} B</td>
                                  <td className="py-3 text-right text-slate-400">
                                    MSS: {device.mss || 'None'}
                                    {device.sackPermitted && ' · SACK'}
                                    {device.windowScale !== undefined && ` · WS: ${device.windowScale}`}
                                  </td>
                                  <td className="py-3 text-right text-slate-400 font-semibold">{device.packetCount} pkts</td>
                                  <td className="py-3 pl-8 font-sans">
                                    {isRogue ? (
                                      <span className="px-1.5 py-0.5 text-[8px] font-sans font-semibold rounded bg-red-500/10 border border-red-500/20 text-red-400 uppercase animate-pulse">
                                        Rogue IoT Breach Warning
                                      </span>
                                    ) : device.inferredOs.includes('IoT') ? (
                                      <span className="px-1.5 py-0.5 text-[8px] font-sans font-semibold rounded bg-amber-500/10 border border-amber-500/20 text-amber-400 uppercase">
                                        Unmanaged IoT / RTOS
                                      </span>
                                    ) : (
                                      <span className="px-1.5 py-0.5 text-[8px] font-sans font-semibold rounded bg-slate-900 border border-slate-850 text-slate-500 uppercase">
                                        Nominal Enterprise Host
                                      </span>
                                    )}
                                  </td>
                                </tr>
                              );
                            })}
                        </tbody>
                      </table>
                    </div>
                  </div>
                </div>
              )}

              {/* TAB 15: CLOUD OVERLAY FORENSICS (VXLAN & GENEVE) */}
              {activeTab === 'overlay' && (
                <div className="flex flex-col gap-6">
                  {/* Info Header Panel */}
                  <div className="bg-indigo-500/5 border border-indigo-500/20 rounded-xl p-5 flex flex-col gap-4 relative overflow-hidden">
                    <div className="absolute top-0 right-0 w-32 h-32 bg-indigo-500/5 rounded-full blur-3xl"></div>
                    <div className="flex items-center justify-between border-b border-indigo-500/10 pb-3">
                      <div className="flex items-center gap-2">
                        <Cloud className="h-4.5 w-4.5 text-indigo-400 animate-pulse" />
                        <span className="text-xs font-semibold text-slate-200">
                          Cloud-Native Overlay Decapsulator (GENEVE & VXLAN)
                        </span>
                      </div>
                      <span className="text-[10px] font-mono text-indigo-400 bg-indigo-500/10 px-2 py-0.5 border border-indigo-500/25 rounded uppercase tracking-wider animate-pulse">
                        Overlay Deep Packet Inspection (DPI)
                      </span>
                    </div>

                    <div className="flex flex-col gap-2">
                      <h4 className="text-xs font-semibold text-indigo-300 font-sans uppercase">Cloud Overlay Tunnel Decapsulation Methodology</h4>
                      <p className="text-[11px] text-slate-400 leading-relaxed font-sans font-medium">
                        In modern cloud architectures (e.g., AWS Gateway Load Balancer, VMware NSX, Kubernetes Calico/Cilium networks), actual workload packets are encapsulated inside UDP-based overlay tunnels like VXLAN (UDP Port 4789) or GENEVE (UDP Port 6081). This hides the true client and server IPs from standard physical routing systems. Our decapsulation engine strips away outer transport headers to reveal actual inner application payloads, protocols, and routing profiles.
                      </p>
                    </div>
                  </div>

                  {/* Warning Cards for Unencrypted Overlay Traffic */}
                  {(() => {
                    const overlayPackets = (analysisResult.packets || []).filter(p => p.overlayData);
                    const unencryptedOverlays = overlayPackets.filter(p => p.overlayData?.isUnencrypted);
                    if (unencryptedOverlays.length === 0) return null;

                    return (
                      <div className="bg-red-500/5 border border-red-500/20 rounded-xl p-5 flex flex-col gap-3 relative overflow-hidden">
                        <div className="absolute top-0 right-0 w-24 h-24 bg-red-500/5 rounded-full blur-2xl"></div>
                        <div className="flex items-center gap-2 text-red-400">
                          <AlertTriangle className="h-5 w-5 animate-pulse" />
                          <span className="text-xs font-bold font-mono uppercase tracking-wider">
                            CRITICAL SECURITY ALARM: Unencrypted Traffic Traversal Inside Cloud Overlay
                          </span>
                        </div>
                        <p className="text-[11px] text-slate-400 leading-relaxed font-sans font-medium">
                          AutoTAC has decapsulated inner payloads and identified unencrypted, cleartext application traffic (<strong className="text-red-300">HTTP/TCP</strong>) traversing virtual cloud overlay tunnels. While tunnels abstract infrastructure transport, they do not encrypt content, exposing sensitive parameters to hop-by-hop sniffing at transit nodes.
                        </p>
                        <div className="text-[11px] bg-red-950/30 p-3 rounded border border-red-950/50 flex flex-col gap-1 text-slate-300 font-mono">
                          <span>• Exposed Path: {unencryptedOverlays[0].overlayData?.innerSrcIp} &rarr; {unencryptedOverlays[0].overlayData?.innerDstIp}</span>
                          <span>• Inner Port: {unencryptedOverlays[0].overlayData?.innerDstPort}</span>
                          <span>• Inner Protocol: {unencryptedOverlays[0].overlayData?.innerProtocol}</span>
                        </div>
                      </div>
                    );
                  })()}

                  {/* Summary Metric Cards */}
                  {(() => {
                    const overlayPackets = (analysisResult.packets || []).filter(p => p.overlayData);
                    const vxlanCount = overlayPackets.filter(p => p.overlayData?.tunnelType === 'VXLAN').length;
                    const geneveCount = overlayPackets.filter(p => p.overlayData?.tunnelType === 'GENEVE').length;
                    const unencryptedCount = overlayPackets.filter(p => p.overlayData?.isUnencrypted).length;

                    return (
                      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                        <div className="bg-slate-950 p-4 rounded-xl border border-slate-900 flex flex-col gap-1.5">
                          <span className="text-[10px] text-slate-500 font-bold uppercase tracking-wider">Total Overlay Packets</span>
                          <span className="text-xl font-bold font-mono text-slate-100 tabular-nums">{overlayPackets.length} packets</span>
                        </div>
                        <div className="bg-slate-950 p-4 rounded-xl border border-slate-900 flex flex-col gap-1.5">
                          <span className="text-[10px] text-blue-400 font-bold uppercase tracking-wider">VXLAN Encapsulated</span>
                          <span className="text-xl font-bold font-mono text-blue-400 tabular-nums">{vxlanCount} packets</span>
                        </div>
                        <div className="bg-slate-950 p-4 rounded-xl border border-slate-900 flex flex-col gap-1.5">
                          <span className="text-[10px] text-indigo-400 font-bold uppercase tracking-wider">GENEVE Encapsulated</span>
                          <span className="text-xl font-bold font-mono text-indigo-400 tabular-nums">{geneveCount} packets</span>
                        </div>
                        <div className="bg-slate-950 p-4 rounded-xl border border-slate-900 flex flex-col gap-1.5">
                          <span className="text-[10px] text-red-400 font-bold uppercase tracking-wider">Unencrypted Inside Overlay</span>
                          <span className="text-xl font-bold font-mono text-red-400 tabular-nums">{unencryptedCount} flows</span>
                        </div>
                      </div>
                    );
                  })()}

                  {/* Data Table */}
                  <div className="bg-slate-900/10 border border-slate-900 rounded-xl p-5 flex flex-col gap-4">
                    <span className="text-xs font-bold text-slate-400 font-mono uppercase tracking-wider">
                      📋 Decapsulated Tunnel Overlay Timeline Log
                    </span>

                    <div className="overflow-x-auto font-mono text-[11px]">
                      <table className="w-full text-left text-xs border-collapse">
                        <thead>
                          <tr className="border-b border-slate-900 text-slate-500 font-medium font-mono font-bold">
                            <th className="py-2.5">Time Offset</th>
                            <th className="py-2.5">Tunnel Type</th>
                            <th className="py-2.5">Outer Tunnel Source &rarr; Dest IP</th>
                            <th className="py-2.5">Decapsulated Inner Source &rarr; Dest IP</th>
                            <th className="py-2.5 text-center font-mono">Inner Port</th>
                            <th className="py-2.5 text-center font-mono font-bold">Inner Protocol</th>
                            <th className="py-2.5 text-center">Encryption Status</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-900 tabular-nums">
                          {(analysisResult.packets || [])
                            .filter(p => p.overlayData)
                            .map((p, idx) => {
                              const o = p.overlayData!;
                              const isUnencrypted = o.isUnencrypted;
                              const tunnelTypeColor = o.tunnelType === 'VXLAN' ? 'text-blue-400 bg-blue-500/10 border-blue-500/20' : 'text-indigo-400 bg-indigo-500/10 border-indigo-500/20';

                              return (
                                <tr key={idx} className="hover:bg-slate-900/30 transition-colors">
                                  <td className="py-3 text-slate-500">
                                    {new Date(p.timestamp).toISOString().split('T')[1].slice(0, -1)}s
                                  </td>
                                  <td className="py-3">
                                    <span className={`px-1.5 py-0.5 text-[9px] font-bold rounded border ${tunnelTypeColor}`}>
                                      {o.tunnelType}
                                    </span>
                                  </td>
                                  <td className="py-3 text-slate-300">
                                    {o.outerSrcIp} &rarr; {o.outerDstIp}
                                  </td>
                                  <td className="py-3 text-white font-bold">
                                    {o.innerSrcIp} &rarr; {o.innerDstIp}
                                  </td>
                                  <td className="py-3 text-center text-slate-400 font-semibold">
                                    {o.innerDstPort || 'N/A'}
                                  </td>
                                  <td className="py-3 text-center">
                                    <span className="font-bold text-cyan-400">{o.innerProtocol}</span>
                                  </td>
                                  <td className="py-3 text-center font-sans">
                                    {isUnencrypted ? (
                                      <span className="px-1.5 py-0.5 text-[8px] font-sans font-semibold rounded bg-red-500/10 border border-red-500/20 text-red-400 uppercase animate-pulse">
                                        ⚠ UNENCRYPTED
                                      </span>
                                    ) : (
                                      <span className="px-1.5 py-0.5 text-[8px] font-sans font-semibold rounded bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 uppercase">
                                        ✓ SECURE (TLS)
                                      </span>
                                    )}
                                  </td>
                                </tr>
                              );
                            })}
                          {(analysisResult.packets || []).filter(p => p.overlayData).length === 0 && (
                            <tr>
                              <td colSpan={7} className="py-12 text-center text-slate-500 italic font-sans text-xs">
                                No cloud-native overlay tunnel frames (VXLAN/GENEVE) discovered in this capture. Works for standard cloud VPC overlay traffic.
                              </td>
                            </tr>
                          )}
                        </tbody>
                      </table>
                    </div>
                  </div>
                </div>
              )}

              {/* TAB 16: BGP & OSPF CONTROL-PLANE DIAGNOSTICS */}
              {activeTab === 'routing' && (
                <div className="flex flex-col gap-6 font-sans">
                  {/* Info Header Panel */}
                  <div className="bg-emerald-500/5 border border-emerald-500/20 rounded-xl p-5 flex flex-col gap-4 relative overflow-hidden">
                    <div className="absolute top-0 right-0 w-32 h-32 bg-emerald-500/5 rounded-full blur-3xl"></div>
                    <div className="flex items-center justify-between border-b border-emerald-500/10 pb-3">
                      <div className="flex items-center gap-2">
                        <GitMerge className="h-4.5 w-4.5 text-emerald-400 animate-pulse" />
                        <span className="text-xs font-semibold text-slate-200">
                          BGP & OSPF Control-Plane Diagnostics Engine
                        </span>
                      </div>
                      <span className="text-[10px] font-mono text-emerald-400 bg-emerald-500/10 px-2 py-0.5 border border-emerald-500/25 rounded uppercase tracking-wider animate-pulse">
                        L3 Core Infrastructure Outage Diagnostics
                      </span>
                    </div>

                    <div className="flex flex-col gap-2">
                      <h4 className="text-xs font-semibold text-emerald-300 uppercase">Automating Core Control-Plane Outage Detection</h4>
                      <p className="text-[11px] text-slate-400 leading-relaxed font-sans">
                        Control-plane failures cause complete enterprise routing blackholes. By performing packet-level analysis of **BGP (TCP Port 179)** session handshakes and **OSPFv2 (IP Protocol 89)** database negotiations, AutoTAC isolates routing loop precursors, configuration mismatches, and peer drops. This panel decodes RFC 4271 BGP Notification state machines and flags OSPF MTU negotiation failures which block database description (DBD) synchronization.
                      </p>
                    </div>
                  </div>

                  {/* Summary Columns */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    {/* Card 1: BGP Peering State */}
                    <div className="bg-slate-900/10 border border-slate-900 rounded-xl p-5 flex flex-col gap-4">
                      <div className="flex items-center justify-between border-b border-slate-900 pb-3">
                        <span className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center gap-2">
                          🌐 BGP Peering State & Peer Drops
                        </span>
                        <span className="text-[9px] font-mono bg-red-500/10 text-red-400 px-1.5 py-0.5 rounded border border-red-500/20">
                          RFC 4271 Decoded
                        </span>
                      </div>

                      <div className="flex flex-col gap-4">
                        {(analysisResult.bgpNotifications || []).map((bgp, i) => (
                          <div key={i} className="p-4 bg-red-950/10 border border-red-500/20 rounded-xl flex flex-col gap-2">
                            <div className="flex justify-between items-center text-[11px] font-mono text-slate-400">
                              <span>Timestamp: {new Date(bgp.timestamp).toISOString().split('T')[1].slice(0, -1)}s</span>
                              <span className="text-red-400 font-bold uppercase tracking-wider bg-red-500/10 px-2 py-0.5 rounded border border-red-500/20 animate-pulse">
                                State: Peering Dropped
                              </span>
                            </div>

                            <div className="grid grid-cols-2 gap-4 mt-1 font-mono text-[11px]">
                              <div>
                                <span className="text-slate-500 block">Router Peer A (Src):</span>
                                <strong className="text-white select-all">{bgp.srcIp}:{bgp.srcPort}</strong>
                              </div>
                              <div>
                                <span className="text-slate-500 block">Router Peer B (Dst):</span>
                                <strong className="text-white select-all">{bgp.dstIp}:{bgp.dstPort}</strong>
                              </div>
                            </div>

                            <div className="border-t border-red-950/40 pt-2.5 mt-2 flex flex-col gap-1">
                              <span className="text-[10px] text-red-400 font-bold font-mono uppercase tracking-wider">
                                Decoded RFC Error: {bgp.errorName} (Code {bgp.errorCode} · Subcode {bgp.subcode})
                              </span>
                              <p className="text-xs font-semibold text-white font-sans mt-0.5">{bgp.subcodeName !== 'Unspecified' ? `${bgp.subcodeName}: ` : ''}{bgp.detail}</p>
                              <span className="text-[9px] text-slate-500 leading-tight mt-1 font-sans italic">
                                Action: Verify BGP keepalive frequency SLA limits, TCP connection status, and hold timers configuration.
                              </span>
                            </div>
                          </div>
                        ))}

                        {(analysisResult.bgpNotifications || []).length === 0 && (
                          <div className="py-12 text-center text-slate-500 italic text-xs">
                            No BGP NOTIFICATION errors or peer drop packets detected in the packet stream. Peering state is nominal.
                          </div>
                        )}
                      </div>
                    </div>

                    {/* Card 2: OSPF Adjacency Health */}
                    <div className="bg-slate-900/10 border border-slate-900 rounded-xl p-5 flex flex-col gap-4">
                      <div className="flex items-center justify-between border-b border-slate-900 pb-3">
                        <span className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center gap-2">
                          🌿 OSPF Adjacency Health & MTU Negotiation
                        </span>
                        <span className="text-[9px] font-mono bg-yellow-500/10 text-yellow-400 px-1.5 py-0.5 rounded border border-yellow-500/20">
                          EXSTART / EXCHANGE Loop Detector
                        </span>
                      </div>

                      <div className="flex flex-col gap-4">
                        {(analysisResult.ospfMismatches || []).map((ospf, i) => (
                          <div key={i} className="p-4 bg-amber-950/15 border border-amber-500/20 rounded-xl flex flex-col gap-2">
                            <div className="flex justify-between items-center text-[11px] font-mono text-slate-400">
                              <span>Timestamp: {new Date(ospf.timestamp).toISOString().split('T')[1].slice(0, -1)}s</span>
                              <span className="text-amber-400 font-bold uppercase tracking-wider bg-amber-500/10 px-2 py-0.5 rounded border border-amber-500/20 animate-pulse">
                                State: Stuck in EXSTART
                              </span>
                            </div>

                            <div className="grid grid-cols-2 gap-4 mt-1 font-mono text-[11px]">
                              <div>
                                <span className="text-slate-500 block">Router ID 1 (IP):</span>
                                <strong className="text-white select-all">{ospf.srcIp}</strong>
                                <span className="text-slate-400 block mt-0.5 bg-slate-950 px-1.5 py-0.5 rounded w-max border border-slate-900">
                                  MTU: {ospf.router1Mtu} B
                                </span>
                              </div>
                              <div>
                                <span className="text-slate-500 block">Router ID 2 (IP):</span>
                                <strong className="text-white select-all">{ospf.dstIp}</strong>
                                <span className="text-slate-400 block mt-0.5 bg-slate-950 px-1.5 py-0.5 rounded w-max border border-slate-900">
                                  MTU: {ospf.router2Mtu} B
                                </span>
                              </div>
                            </div>

                            <div className="border-t border-amber-950/40 pt-2.5 mt-2 flex flex-col gap-1">
                              <span className="text-[10px] text-amber-500 font-bold font-mono uppercase tracking-wider">
                                Adjacency Verdict: {ospf.verdict}
                              </span>
                              <p className="text-xs font-sans font-medium text-slate-300 mt-1">{ospf.detail}</p>
                              <span className="text-[9px] text-slate-500 leading-tight mt-1 font-sans italic">
                                Technical Alert: OSPF neighbors will forever cycle between EXSTART and EXCHANGE states and never reach FULL adjacency because their IP MTUs disagree. The router with the smaller MTU will discard DBD packets exceeding its limit.
                              </span>
                            </div>
                          </div>
                        ))}

                        {(analysisResult.ospfMismatches || []).length === 0 && (
                          <div className="py-12 text-center text-slate-500 italic text-xs">
                            No OSPF MTU mismatches or sticky negotiation states detected. Database Description MTUs are matching.
                          </div>
                        )}
                      </div>
                    </div>
                  </div>

                  {/* Core Routing Table Protocol Packets Log */}
                  <div className="bg-slate-900/10 border border-slate-900 rounded-xl p-5 flex flex-col gap-4">
                    <span className="text-xs font-bold text-slate-400 font-mono uppercase tracking-wider">
                      📋 Decoded BGP and OSPF Protocol Timeline Log
                    </span>

                    <div className="overflow-x-auto font-mono text-[11px]">
                      <table className="w-full text-left text-xs border-collapse font-sans">
                        <thead>
                          <tr className="border-b border-slate-900 text-slate-500 font-medium font-mono font-bold">
                            <th className="py-2.5">Time Offset</th>
                            <th className="py-2.5">Protocol</th>
                            <th className="py-2.5">Source Router &rarr; Destination Router</th>
                            <th className="py-2.5 font-mono font-bold text-left">BGP/OSPF Specific Payload Parameters</th>
                            <th className="py-2.5 text-right font-mono font-bold">Packet Length</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-900 tabular-nums text-slate-300">
                          {(analysisResult.packets || [])
                            .filter(p => p.protocol === 'BGP' || p.protocol === 'OSPF')
                            .map((p, idx) => {
                              const isBgp = p.protocol === 'BGP';
                              const protoColor = isBgp ? 'text-cyan-400 bg-cyan-500/10 border-cyan-500/20' : 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20';

                              return (
                                <tr key={idx} className="hover:bg-slate-900/30 transition-colors">
                                  <td className="py-3 text-slate-500">
                                    {new Date(p.timestamp).toISOString().split('T')[1].slice(0, -1)}s
                                  </td>
                                  <td className="py-3 font-sans">
                                    <span className={`px-1.5 py-0.5 text-[9px] font-bold rounded border ${protoColor}`}>
                                      {p.protocol}
                                    </span>
                                  </td>
                                  <td className="py-3 text-white font-bold select-all">
                                    {p.srcIp} &rarr; {p.dstIp}
                                  </td>
                                  <td className="py-3 font-sans text-xs">
                                    {p.info}
                                  </td>
                                  <td className="py-3 text-right text-slate-400 font-mono">
                                    {p.length} B
                                  </td>
                                </tr>
                              );
                            })}
                          {(analysisResult.packets || []).filter(p => p.protocol === 'BGP' || p.protocol === 'OSPF').length === 0 && (
                            <tr>
                              <td colSpan={5} className="py-12 text-center text-slate-500 italic font-sans text-xs">
                                No BGP or OSPF frames parsed in this network trace.
                              </td>
                            </tr>
                          )}
                        </tbody>
                      </table>
                    </div>
                  </div>
                </div>
              )}

              {/* TAB 17: VOICE & TELEPHONY HEALTH (VOIP, SIP & RTP QUALITY ANALYZER) */}
              {activeTab === 'voip' && (
                <div className="flex flex-col gap-6 font-sans">
                  {/* Info Header Panel */}
                  <div className="bg-violet-500/5 border border-violet-500/20 rounded-xl p-5 flex flex-col gap-4 relative overflow-hidden">
                    <div className="absolute top-0 right-0 w-32 h-32 bg-violet-500/5 rounded-full blur-3xl"></div>
                    <div className="flex items-center justify-between border-b border-violet-500/10 pb-3">
                      <div className="flex items-center gap-2">
                        <PhoneCall className="h-4.5 w-4.5 text-violet-400 animate-pulse" />
                        <span className="text-xs font-semibold text-slate-200">
                          VoIP & SIP/RTP Quality Analyzer Engine
                        </span>
                      </div>
                      <span className="text-[10px] font-mono text-violet-400 bg-violet-500/10 px-2 py-0.5 border border-violet-500/25 rounded uppercase tracking-wider animate-pulse">
                        RFC 3261 Signaling & RFC 3550 Real-Time Transport
                      </span>
                    </div>

                    <div className="flex flex-col gap-2">
                      <h4 className="text-xs font-semibold text-violet-300 uppercase">
                        Diagnosing Telephony Signaling Failures & Audio Degradation
                      </h4>
                      <p className="text-[11px] text-slate-400 leading-relaxed font-sans">
                        Enterprise VoIP relies on UDP without transmission control, making it extremely vulnerable to WAN packet loss and jitter. AutoTAC filters for **SIP (UDP/TCP 5060)** signaling transactions to detect failed call setup responses (<span className="text-amber-400 font-semibold font-mono">4xx Client Errors</span>, <span className="text-red-400 font-semibold font-mono">5xx Server Errors</span>, and <span className="text-rose-400 font-semibold font-mono">6xx Global Failures</span>), maps dialogue Call-IDs, and tracks **RTP Sequence Numbers** to measure audio packet loss percentages, diagnosing robotic voice distortion and choppy speech.
                      </p>
                    </div>
                  </div>

                  {/* Top Quality Metric Cards Grid */}
                  <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                    {/* Card 1: Warning Metric Card - Max RTP Packet Loss % (Requirement #4) */}
                    <div className={`p-4 rounded-xl border flex flex-col justify-between transition-all ${
                      (analysisResult.voipAnalysis?.maxRtpPacketLossPercent || 0) >= 3.0
                        ? 'bg-red-950/20 border-red-500/40 shadow-lg shadow-red-950/30'
                        : (analysisResult.voipAnalysis?.maxRtpPacketLossPercent || 0) > 0
                        ? 'bg-amber-950/20 border-amber-500/30'
                        : 'bg-slate-900/40 border-slate-900'
                    }`}>
                      <div className="flex items-center justify-between">
                        <span className="text-[11px] font-mono uppercase tracking-wider text-slate-400 font-semibold">
                          Max RTP Packet Loss %
                        </span>
                        {(analysisResult.voipAnalysis?.maxRtpPacketLossPercent || 0) >= 3.0 ? (
                          <VolumeX className="h-4 w-4 text-red-400 animate-bounce" />
                        ) : (
                          <Volume2 className="h-4 w-4 text-emerald-400" />
                        )}
                      </div>
                      <div className="my-2">
                        <span className={`text-2xl font-bold font-mono tracking-tight ${
                          (analysisResult.voipAnalysis?.maxRtpPacketLossPercent || 0) >= 3.0
                            ? 'text-red-400'
                            : (analysisResult.voipAnalysis?.maxRtpPacketLossPercent || 0) > 0
                            ? 'text-amber-400'
                            : 'text-emerald-400'
                        }`}>
                          {analysisResult.voipAnalysis?.maxRtpPacketLossPercent !== undefined
                            ? `${analysisResult.voipAnalysis.maxRtpPacketLossPercent.toFixed(1)}%`
                            : '0.0%'}
                        </span>
                      </div>
                      <div className="text-[10px] leading-tight">
                        {(analysisResult.voipAnalysis?.maxRtpPacketLossPercent || 0) >= 3.0 ? (
                          <span className="text-red-300 font-medium flex items-center gap-1">
                            <AlertTriangle className="h-3 w-3 text-red-400 shrink-0" />
                            Severe Voice Jitter & Robotic Audio
                          </span>
                        ) : (analysisResult.voipAnalysis?.maxRtpPacketLossPercent || 0) > 0 ? (
                          <span className="text-amber-300 font-medium">Mild Jitter (Sub-optimal QoS)</span>
                        ) : (
                          <span className="text-emerald-400 font-medium">Nominal Audio Quality</span>
                        )}
                      </div>
                    </div>

                    {/* Card 2: SIP Signaling Failures */}
                    <div className="p-4 rounded-xl border bg-slate-900/40 border-slate-900 flex flex-col justify-between">
                      <div className="flex items-center justify-between">
                        <span className="text-[11px] font-mono uppercase tracking-wider text-slate-400 font-semibold">
                          Signaling Failures
                        </span>
                        <PhoneOff className="h-4 w-4 text-red-400" />
                      </div>
                      <div className="my-2">
                        <span className={`text-2xl font-bold font-mono tracking-tight ${
                          (analysisResult.voipAnalysis?.failedCallsCount || 0) > 0 ? 'text-amber-400' : 'text-slate-200'
                        }`}>
                          {analysisResult.voipAnalysis?.failedCallsCount || 0}
                        </span>
                      </div>
                      <span className="text-[10px] text-slate-500">
                        Flagged 4xx, 5xx, or 6xx Responses
                      </span>
                    </div>

                    {/* Card 3: Total Monitored Calls */}
                    <div className="p-4 rounded-xl border bg-slate-900/40 border-slate-900 flex flex-col justify-between">
                      <div className="flex items-center justify-between">
                        <span className="text-[11px] font-mono uppercase tracking-wider text-slate-400 font-semibold">
                          Active SIP Dialogues
                        </span>
                        <Radio className="h-4 w-4 text-violet-400" />
                      </div>
                      <div className="my-2">
                        <span className="text-2xl font-bold font-mono tracking-tight text-slate-200">
                          {analysisResult.voipAnalysis?.totalCalls || 0}
                        </span>
                      </div>
                      <span className="text-[10px] text-slate-500">
                        Call-ID Mapped Sessions
                      </span>
                    </div>

                    {/* Card 4: Average Jitter (ms) */}
                    <div className="p-4 rounded-xl border bg-slate-900/40 border-slate-900 flex flex-col justify-between">
                      <div className="flex items-center justify-between">
                        <span className="text-[11px] font-mono uppercase tracking-wider text-slate-400 font-semibold">
                          Mean Transit Jitter
                        </span>
                        <Activity className="h-4 w-4 text-cyan-400" />
                      </div>
                      <div className="my-2">
                        <span className="text-2xl font-bold font-mono tracking-tight text-cyan-400">
                          {analysisResult.voipAnalysis?.averageJitterMs !== undefined
                            ? `${analysisResult.voipAnalysis.averageJitterMs} ms`
                            : '0.0 ms'}
                        </span>
                      </div>
                      <span className="text-[10px] text-slate-500">
                        RFC 3550 Interarrival Variance
                      </span>
                    </div>
                  </div>

                  {/* REQUIREMENT 4: Active SIP Calls Table */}
                  <div className="bg-slate-900/20 border border-slate-900 rounded-xl p-5 flex flex-col gap-4">
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-900 pb-3">
                      <div className="flex items-center gap-2">
                        <PhoneCall className="h-4 w-4 text-violet-400" />
                        <span className="text-xs font-bold text-slate-200 uppercase tracking-wider">
                          Active SIP Calls
                        </span>
                        <span className="text-[10px] font-mono text-slate-400 bg-slate-900 px-2 py-0.5 rounded border border-slate-800">
                          {analysisResult.voipAnalysis?.calls.length || 0} Sessions
                        </span>
                      </div>

                      {/* Filter controls */}
                      <div className="flex items-center gap-2 flex-wrap">
                        <div className="relative">
                          <input
                            type="text"
                            placeholder="Filter Caller, Callee, Call-ID..."
                            value={voipSearchQuery}
                            onChange={(e) => setVoipSearchQuery(e.target.value)}
                            className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-violet-500 w-48 font-mono text-[11px]"
                          />
                        </div>
                        <div className="flex rounded-lg border border-slate-800 bg-slate-950 p-0.5 text-xs">
                          <button
                            type="button"
                            onClick={() => setVoipStatusFilter('all')}
                            className={`px-2 py-0.5 rounded text-[11px] font-medium transition-colors ${
                              voipStatusFilter === 'all' ? 'bg-violet-500/20 text-violet-300 font-semibold' : 'text-slate-400 hover:text-slate-200'
                            }`}
                          >
                            All ({analysisResult.voipAnalysis?.calls.length || 0})
                          </button>
                          <button
                            type="button"
                            onClick={() => setVoipStatusFilter('failed')}
                            className={`px-2 py-0.5 rounded text-[11px] font-medium transition-colors ${
                              voipStatusFilter === 'failed' ? 'bg-red-500/20 text-red-300 font-semibold' : 'text-slate-400 hover:text-slate-200'
                            }`}
                          >
                            Failed Only ({analysisResult.voipAnalysis?.failedCallsCount || 0})
                          </button>
                          <button
                            type="button"
                            onClick={() => setVoipStatusFilter('nominal')}
                            className={`px-2 py-0.5 rounded text-[11px] font-medium transition-colors ${
                              voipStatusFilter === 'nominal' ? 'bg-emerald-500/20 text-emerald-300 font-semibold' : 'text-slate-400 hover:text-slate-200'
                            }`}
                          >
                            Nominal ({(analysisResult.voipAnalysis?.calls || []).filter(c => !c.isFailed).length})
                          </button>
                        </div>
                      </div>
                    </div>

                    {/* Table showing [Caller, Callee, Call-ID, SIP Status] */}
                    <div className="overflow-x-auto">
                      <table className="w-full text-left text-xs border-collapse">
                        <thead>
                          <tr className="border-b border-slate-900 text-slate-400 font-mono font-medium">
                            <th className="py-2.5 px-3">Caller</th>
                            <th className="py-2.5 px-3">Callee</th>
                            <th className="py-2.5 px-3 font-mono">Call-ID</th>
                            <th className="py-2.5 px-3">SIP Status</th>
                            <th className="py-2.5 px-3 text-right">Actions</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-900/60 font-sans text-xs">
                          {(analysisResult.voipAnalysis?.calls || [])
                            .filter(call => {
                              if (voipStatusFilter === 'failed' && !call.isFailed) return false;
                              if (voipStatusFilter === 'nominal' && call.isFailed) return false;
                              if (voipSearchQuery.trim()) {
                                const q = voipSearchQuery.toLowerCase();
                                return (
                                  call.caller.toLowerCase().includes(q) ||
                                  call.callee.toLowerCase().includes(q) ||
                                  call.callId.toLowerCase().includes(q) ||
                                  call.status.toLowerCase().includes(q)
                                );
                              }
                              return true;
                            })
                            .map((call, idx) => {
                              const isSelected = selectedVoipCallId === call.callId;
                              let statusBadgeStyle = 'bg-emerald-500/10 text-emerald-400 border-emerald-500/25';
                              if (call.statusCode && call.statusCode >= 400 && call.statusCode < 500) {
                                statusBadgeStyle = 'bg-amber-500/15 text-amber-300 border-amber-500/30';
                              } else if (call.statusCode && call.statusCode >= 500 && call.statusCode < 600) {
                                statusBadgeStyle = 'bg-red-500/15 text-red-300 border-red-500/30';
                              } else if (call.statusCode && call.statusCode >= 600) {
                                statusBadgeStyle = 'bg-rose-500/15 text-rose-300 border-rose-500/30';
                              }

                              return (
                                <tr
                                  key={idx}
                                  onClick={() => setSelectedVoipCallId(isSelected ? null : call.callId)}
                                  className={`hover:bg-slate-900/40 transition-colors cursor-pointer ${
                                    isSelected ? 'bg-violet-950/20 border-l-2 border-l-violet-500' : ''
                                  }`}
                                >
                                  {/* Caller */}
                                  <td className="py-3 px-3">
                                    <div className="flex flex-col">
                                      <span className="font-semibold text-slate-100">{call.caller}</span>
                                      <span className="text-[10px] font-mono text-slate-500">{call.srcIp}:5060</span>
                                    </div>
                                  </td>

                                  {/* Callee */}
                                  <td className="py-3 px-3">
                                    <div className="flex flex-col">
                                      <span className="font-semibold text-slate-100">{call.callee}</span>
                                      <span className="text-[10px] font-mono text-slate-500">{call.dstIp}:5060</span>
                                    </div>
                                  </td>

                                  {/* Call-ID */}
                                  <td className="py-3 px-3 font-mono text-[11px]">
                                    <div className="flex items-center gap-1.5 group">
                                      <span className="text-cyan-300 select-all max-w-[220px] truncate" title={call.callId}>
                                        {call.callId}
                                      </span>
                                      <button
                                        type="button"
                                        onClick={(e) => {
                                          e.stopPropagation();
                                          handleCopyCallId(call.callId);
                                        }}
                                        className="opacity-0 group-hover:opacity-100 hover:text-white text-slate-500 transition-opacity p-0.5 rounded cursor-pointer"
                                        title="Copy Call-ID"
                                      >
                                        {copiedCallId === call.callId ? (
                                          <Check className="h-3 w-3 text-emerald-400" />
                                        ) : (
                                          <Copy className="h-3 w-3" />
                                        )}
                                      </button>
                                    </div>
                                  </td>

                                  {/* SIP Status */}
                                  <td className="py-3 px-3">
                                    <div className="flex items-center gap-2">
                                      <span className={`px-2 py-0.5 text-[10px] font-bold rounded border font-mono tracking-tight ${statusBadgeStyle}`}>
                                        {call.status}
                                      </span>
                                      {call.isFailed && call.failureReason && (
                                        <span className="text-[10px] text-slate-400 italic hidden sm:inline">
                                          ({call.failureReason})
                                        </span>
                                      )}
                                    </div>
                                  </td>

                                  {/* Actions */}
                                  <td className="py-3 px-3 text-right">
                                    <button
                                      type="button"
                                      onClick={(e) => {
                                        e.stopPropagation();
                                        setSelectedVoipCallId(isSelected ? null : call.callId);
                                      }}
                                      className="px-2 py-1 bg-slate-900 hover:bg-slate-800 text-slate-300 rounded text-[11px] font-medium border border-slate-800 transition-colors"
                                    >
                                      {isSelected ? 'Hide Ladder' : 'View Ladder'}
                                    </button>
                                  </td>
                                </tr>
                              );
                            })}

                          {(analysisResult.voipAnalysis?.calls || []).length === 0 && (
                            <tr>
                              <td colSpan={5} className="py-12 text-center text-slate-500 italic text-xs">
                                No SIP call signaling sessions detected in this network trace.
                              </td>
                            </tr>
                          )}
                        </tbody>
                      </table>
                    </div>
                  </div>

                  {/* REQUIREMENT 4: Warning Metric Card & Callout Below SIP Table */}
                  <div className={`rounded-xl border p-5 flex flex-col md:flex-row items-start md:items-center justify-between gap-4 transition-all ${
                    (analysisResult.voipAnalysis?.maxRtpPacketLossPercent || 0) >= 3.0
                      ? 'bg-gradient-to-r from-red-950/40 via-red-900/20 to-slate-950 border-red-500/40 shadow-xl shadow-red-950/20'
                      : 'bg-slate-900/30 border-slate-900'
                  }`}>
                    <div className="flex items-start gap-3.5">
                      <div className={`p-3 rounded-xl border shrink-0 ${
                        (analysisResult.voipAnalysis?.maxRtpPacketLossPercent || 0) >= 3.0
                          ? 'bg-red-500/20 text-red-400 border-red-500/30 animate-pulse'
                          : 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30'
                      }`}>
                        {(analysisResult.voipAnalysis?.maxRtpPacketLossPercent || 0) >= 3.0 ? (
                          <AlertTriangle className="h-6 w-6" />
                        ) : (
                          <CheckCircle className="h-6 w-6" />
                        )}
                      </div>

                      <div className="flex flex-col gap-1">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="text-xs font-bold text-white uppercase tracking-wider">
                            Telephony Audio Health Warning Metric
                          </span>
                          <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border uppercase ${
                            (analysisResult.voipAnalysis?.maxRtpPacketLossPercent || 0) >= 3.0
                              ? 'bg-red-500/15 text-red-400 border-red-500/30'
                              : 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30'
                          }`}>
                            {(analysisResult.voipAnalysis?.maxRtpPacketLossPercent || 0) >= 3.0
                              ? 'Severe Voice Jitter & Robotic Audio'
                              : 'Acceptable Voice Intelligibility'}
                          </span>
                        </div>

                        <p className="text-xs text-slate-300 leading-relaxed max-w-3xl">
                          {(analysisResult.voipAnalysis?.maxRtpPacketLossPercent || 0) >= 3.0 ? (
                            <>
                              ⚠️ <strong>Critical Telephony Degradation:</strong> Max RTP Packet Loss is <strong className="text-red-400 font-mono">{(analysisResult.voipAnalysis?.maxRtpPacketLossPercent || 0).toFixed(1)}%</strong>. In real-time UDP streams, missing sequence numbers prevent Packet Loss Concealment (PLC) interpolation, creating audible gaps, choppy syllables, and severe robotic audio for voice callers.
                            </>
                          ) : (
                            <>
                              Nominal RTP transport: Max observed packet loss is <span className="text-emerald-400 font-mono font-bold">{(analysisResult.voipAnalysis?.maxRtpPacketLossPercent || 0).toFixed(1)}%</span>. UDP sequence numbers are consecutive without jitter buffer exhaustion.
                            </>
                          )}
                        </p>
                      </div>
                    </div>

                    <div className="flex flex-col items-end shrink-0 pl-4 border-l border-slate-900/80">
                      <span className="text-[10px] font-mono text-slate-500 uppercase tracking-wider">
                        Max RTP Packet Loss %
                      </span>
                      <span className={`text-3xl font-extrabold font-mono tracking-tight ${
                        (analysisResult.voipAnalysis?.maxRtpPacketLossPercent || 0) >= 3.0 ? 'text-red-400' : 'text-emerald-400'
                      }`}>
                        {(analysisResult.voipAnalysis?.maxRtpPacketLossPercent || 0).toFixed(1)}%
                      </span>
                      <span className="text-[10px] text-slate-500">
                        Threshold: &gt; 3.0% causes robotic audio
                      </span>
                    </div>
                  </div>

                  {/* Monitored RTP Audio Streams Table */}
                  <div className="bg-slate-900/20 border border-slate-900 rounded-xl p-5 flex flex-col gap-4">
                    <div className="flex items-center justify-between border-b border-slate-900 pb-3">
                      <div className="flex items-center gap-2">
                        <Volume2 className="h-4 w-4 text-cyan-400" />
                        <span className="text-xs font-bold text-slate-200 uppercase tracking-wider">
                          Monitored RTP Audio Streams (SSRC Analysis)
                        </span>
                      </div>
                      <span className="text-[10px] font-mono text-slate-500 bg-slate-900 px-2 py-0.5 rounded border border-slate-800">
                        {analysisResult.voipAnalysis?.rtpStreams.length || 0} Streams
                      </span>
                    </div>

                    <div className="overflow-x-auto">
                      <table className="w-full text-left text-xs border-collapse">
                        <thead>
                          <tr className="border-b border-slate-900 text-slate-400 font-mono font-medium">
                            <th className="py-2.5 px-3">SSRC Identifier</th>
                            <th className="py-2.5 px-3">Source Endpoint &rarr; Destination Endpoint</th>
                            <th className="py-2.5 px-3">Codec / Payload</th>
                            <th className="py-2.5 px-3 text-right">Pkts Received / Expected</th>
                            <th className="py-2.5 px-3 text-right">Lost Packets</th>
                            <th className="py-2.5 px-3 text-right">Packet Loss %</th>
                            <th className="py-2.5 px-3">Quality Verdict</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-900/60 font-sans text-xs">
                          {(analysisResult.voipAnalysis?.rtpStreams || []).map((stream, idx) => {
                            const isHighLoss = stream.packetLossPercent >= 3.0;

                            return (
                              <tr key={idx} className="hover:bg-slate-900/30 transition-colors">
                                <td className="py-3 px-3 font-mono font-bold text-cyan-300">
                                  {stream.ssrcHex}
                                </td>
                                <td className="py-3 px-3 font-mono text-[11px] text-slate-300">
                                  {stream.srcIp}:{stream.srcPort} &rarr; {stream.dstIp}:{stream.dstPort}
                                </td>
                                <td className="py-3 px-3 font-mono text-slate-400">
                                  <span className="bg-slate-950 px-1.5 py-0.5 rounded border border-slate-800">
                                    {stream.payloadName} (PT {stream.payloadType})
                                  </span>
                                </td>
                                <td className="py-3 px-3 text-right font-mono text-slate-300">
                                  {stream.packetsReceived} / {stream.packetsExpected}
                                </td>
                                <td className="py-3 px-3 text-right font-mono">
                                  <span className={stream.packetsLost > 0 ? 'text-red-400 font-bold' : 'text-slate-500'}>
                                    {stream.packetsLost}
                                  </span>
                                </td>
                                <td className="py-3 px-3 text-right font-mono font-bold">
                                  <span className={isHighLoss ? 'text-red-400' : 'text-emerald-400'}>
                                    {stream.packetLossPercent.toFixed(1)}%
                                  </span>
                                </td>
                                <td className="py-3 px-3">
                                  <span className={`px-2 py-0.5 text-[10px] font-bold rounded border ${
                                    isHighLoss
                                      ? 'bg-red-500/15 text-red-300 border-red-500/30 animate-pulse'
                                      : 'bg-emerald-500/15 text-emerald-400 border-emerald-500/25'
                                  }`}>
                                    {stream.qualityVerdict}
                                  </span>
                                </td>
                              </tr>
                            );
                          })}

                          {(analysisResult.voipAnalysis?.rtpStreams || []).length === 0 && (
                            <tr>
                              <td colSpan={7} className="py-12 text-center text-slate-500 italic text-xs">
                                No RTP audio streams parsed in this capture trace.
                              </td>
                            </tr>
                          )}
                        </tbody>
                      </table>
                    </div>
                  </div>

                  {/* Interactive Selected Call Detail Ladder Drawer */}
                  {selectedVoipCallId && (
                    <div className="bg-slate-950 border border-violet-500/30 rounded-xl p-5 flex flex-col gap-4">
                      <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                        <div className="flex items-center gap-2">
                          <Radio className="h-4 w-4 text-violet-400" />
                          <span className="text-xs font-bold text-slate-200">
                            SIP Ladder Signaling Inspection: <span className="text-violet-300 font-mono">{selectedVoipCallId}</span>
                          </span>
                        </div>
                        <button
                          type="button"
                          onClick={() => setSelectedVoipCallId(null)}
                          className="text-xs text-slate-500 hover:text-slate-300"
                        >
                          Close Inspector &times;
                        </button>
                      </div>

                      <div className="flex flex-col gap-2">
                        {(analysisResult.packets || [])
                          .filter(p => p.sipData && p.sipData.callId === selectedVoipCallId)
                          .map((p, pIdx) => {
                            const isResp = p.sipData?.isResponse;
                            const code = p.sipData?.statusCode;
                            const isErr = code && code >= 400;

                            return (
                              <div
                                key={pIdx}
                                className={`p-3 rounded-lg border text-xs font-mono flex items-center justify-between ${
                                  isErr
                                    ? 'bg-red-950/20 border-red-500/30 text-red-200'
                                    : 'bg-slate-900/50 border-slate-800 text-slate-300'
                                }`}
                              >
                                <div className="flex items-center gap-3">
                                  <span className="text-slate-500 text-[10px]">
                                    +{((p.timestamp - (analysisResult.packets[0]?.timestamp || 0)) / 1000).toFixed(3)}s
                                  </span>
                                  <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                                    isResp ? 'bg-cyan-500/10 text-cyan-300 border border-cyan-500/20' : 'bg-purple-500/10 text-purple-300 border border-purple-500/20'
                                  }`}>
                                    {isResp ? `RESPONSE ${code}` : p.sipData?.method}
                                  </span>
                                  <span className="text-white font-semibold">
                                    {p.srcIp} &rarr; {p.dstIp}
                                  </span>
                                </div>
                                <span className="text-slate-400 text-[11px] truncate max-w-md">
                                  {p.info}
                                </span>
                              </div>
                            );
                          })}
                      </div>
                    </div>
                  )}

                  {/* Python & Streamlit Code Synthesizer (st.code Equivalent) */}
                  <div className="bg-slate-950 border border-slate-800 rounded-xl overflow-hidden flex flex-col">
                    <div className="flex items-center justify-between px-5 py-3 bg-slate-900/60 border-b border-slate-800">
                      <div className="flex items-center gap-2">
                        <FileCode className="h-4 w-4 text-emerald-400" />
                        <span className="text-xs font-bold text-slate-200">
                          Python Streamlit Diagnostics Engine: autotac_voip_analyzer.py
                        </span>
                        <span className="text-[10px] font-mono text-slate-400 bg-slate-900 px-2 py-0.5 rounded border border-slate-800">
                          Python 3.10+ · Streamlit · Scapy
                        </span>
                      </div>
                      <div className="flex items-center gap-2">
                        <button
                          type="button"
                          onClick={() => downloadFile('autotac_voip_analyzer.py', voipPythonScriptContent, 'text/x-python')}
                          className="flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium text-slate-400 hover:text-slate-200 hover:bg-slate-800 rounded transition-colors cursor-pointer"
                        >
                          <Download className="h-3.5 w-3.5" />
                          <span>Download .py</span>
                        </button>
                        <button
                          type="button"
                          onClick={() => {
                            navigator.clipboard.writeText(voipPythonScriptContent);
                            setCopiedVoipScript(true);
                            setTimeout(() => setCopiedVoipScript(false), 2000);
                          }}
                          className="flex items-center gap-1.5 px-3 py-1 bg-emerald-500/10 hover:bg-emerald-500/20 border border-emerald-500/30 text-emerald-300 rounded text-xs font-semibold transition-all cursor-pointer"
                        >
                          {copiedVoipScript ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
                          <span>{copiedVoipScript ? 'Copied Python Script!' : 'Copy Streamlit Code'}</span>
                        </button>
                      </div>
                    </div>

                    <div className="p-4 bg-slate-950 font-mono text-[11px] text-emerald-300 overflow-x-auto select-all leading-relaxed whitespace-pre border-l-2 border-l-emerald-500 max-h-96">
                      <code>{voipPythonScriptContent}</code>
                    </div>

                    <div className="px-5 py-2.5 bg-slate-900/40 border-t border-slate-800/80 flex items-center justify-between text-[11px] text-slate-500 font-sans">
                      <span>Execute directly in your terminal: <code className="text-emerald-400 font-mono">streamlit run autotac_voip_analyzer.py</code></span>
                      <span>Requires <code className="text-slate-400 font-mono">pip install streamlit scapy pandas</code></span>
                    </div>
                  </div>
                </div>
              )}
            </>
          )}

          {!analysisResult && !isParsing && (
            <div className="flex flex-col items-center justify-center py-24 gap-4 bg-slate-900/10 border border-slate-900 rounded-2xl p-6 text-center max-w-xl mx-auto mt-12">
              <Activity className="h-12 w-12 text-slate-500 animate-pulse" />
              <div>
                <h3 className="text-sm font-semibold text-white">No Capture Session Active</h3>
                <p className="text-xs text-slate-400 leading-relaxed mt-1">
                  Upload a standard binary network trace file (`.pcap` / `.pcapng`) from your desktop, or click one of the preset scenario templates above to run real-time packet-level diagnostics instantly.
                </p>
              </div>
            </div>
          )}
        </main>
      </div>

      {/* SaaS Dashboard Footer */}
      <footer className="border-t border-slate-900 px-6 py-4 bg-slate-950 text-slate-500 text-xs flex flex-col sm:flex-row items-center justify-between gap-4 mt-auto">
        <div className="flex flex-col gap-1.5">
          <span>&copy; {new Date().getFullYear()} AutoTAC Analyzer. All rights reserved.</span>
          <span className="text-[10px] font-mono tracking-wider text-cyan-500/80 font-semibold uppercase">
            Lead L3 Forensic Engineer Signature: BHARANIDHARAN SIVASAMY
          </span>
        </div>
        <div className="flex items-center gap-4 text-[11px] text-slate-600 font-medium">
          <a href="#privacy" className="hover:underline">Security Framework</a>
          <span>·</span>
          <a href="#terms" className="hover:underline">TAC SLA Compliance</a>
          <span>·</span>
          <span>Enterprise Threshold SLA: 1% loss</span>
        </div>
      </footer>

      {/* THREAT-TO-CODE IDS RULE SYNTHESIZER MODAL */}
      {idsModalOpen && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-md flex items-center justify-center p-4 overflow-y-auto">
          <div className="relative w-full max-w-4xl bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl overflow-hidden flex flex-col max-h-[90vh] my-auto">
            {/* Modal Header */}
            <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800 bg-slate-950/60">
              <div className="flex items-center gap-3">
                <div className="h-9 w-9 rounded-lg bg-gradient-to-br from-rose-500/20 to-purple-500/20 border border-rose-500/30 flex items-center justify-center">
                  <ShieldAlert className="h-5 w-5 text-rose-400" />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <h3 className="text-sm font-bold text-white tracking-tight">
                      Threat-to-Code IDS Rule Synthesizer
                    </h3>
                    <span className="px-2 py-0.5 rounded text-[9px] font-mono font-bold bg-cyan-500/10 border border-cyan-500/20 text-cyan-400">
                      Gemini Detection Engineering
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-400 mt-0.5">
                    Automated translation from captured network anomaly signature to deployable Suricata IDS and SIEM Sigma rules
                  </p>
                </div>
              </div>
              <button
                type="button"
                onClick={() => setIdsModalOpen(false)}
                className="text-slate-400 hover:text-white p-1.5 rounded-lg hover:bg-slate-800 transition-colors"
                title="Close Synthesizer"
              >
                ✕
              </button>
            </div>

            {/* Modal Body */}
            <div className="p-6 overflow-y-auto flex flex-col gap-5">
              {/* Target Packet Telemetry Bar */}
              {idsActivePacket && (
                <div className="bg-slate-950 border border-slate-850 rounded-xl p-3 flex flex-wrap items-center justify-between gap-3 text-xs font-mono">
                  <div className="flex items-center gap-3">
                    <span className="text-slate-500">Packet #{idsActivePacket.index + 1}</span>
                    <span className="text-slate-600">·</span>
                    <span className="text-cyan-400 font-semibold">{idsActivePacket.protocol}</span>
                    <span className="text-slate-600">·</span>
                    <span className="text-slate-200">
                      {idsActivePacket.srcIp}{idsActivePacket.srcPort ? `:${idsActivePacket.srcPort}` : ''} &rarr; {idsActivePacket.dstIp}{idsActivePacket.dstPort ? `:${idsActivePacket.dstPort}` : ''}
                    </span>
                  </div>
                  {getPacketAnomalyBadge(idsActivePacket) && (
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${getPacketAnomalyBadge(idsActivePacket)?.color}`}>
                      {getPacketAnomalyBadge(idsActivePacket)?.label}
                    </span>
                  )}
                </div>
              )}

              {/* Loading State */}
              {idsLoading && (
                <div className="py-16 flex flex-col items-center justify-center gap-4 text-center">
                  <div className="relative">
                    <div className="w-12 h-12 rounded-full border-2 border-rose-500/20 border-t-rose-500 animate-spin" />
                    <Sparkles className="absolute inset-0 m-auto h-5 w-5 text-rose-400 animate-pulse" />
                  </div>
                  <div className="flex flex-col gap-1 max-w-md">
                    <h4 className="text-sm font-semibold text-white">Synthesizing Detection Rules...</h4>
                    <p className="text-xs text-slate-400 leading-relaxed">
                      Deconstructing Layer 3 IP headers, Layer 4 ports/flags, and Layer 7 application payloads into strict Suricata signatures and SIEM Sigma YAML.
                    </p>
                  </div>
                </div>
              )}

              {/* Error State */}
              {idsError && !idsLoading && (
                <div className="bg-rose-950/20 border border-rose-500/30 rounded-xl p-4 flex items-start gap-3">
                  <AlertTriangle className="h-5 w-5 text-rose-400 shrink-0 mt-0.5" />
                  <div className="flex flex-col gap-1 flex-1">
                    <h4 className="text-xs font-bold text-rose-300">Synthesis Encountered an Error</h4>
                    <p className="text-xs text-rose-400/90">{idsError}</p>
                    <button
                      type="button"
                      onClick={() => idsActivePacket && handleGenerateIdsRule(idsActivePacket)}
                      className="mt-2 self-start px-3 py-1 bg-rose-500/20 hover:bg-rose-500/30 border border-rose-500/40 text-rose-200 rounded text-xs font-semibold transition-colors"
                    >
                      Retry Generation
                    </button>
                  </div>
                </div>
              )}

              {/* Generated Result */}
              {idsRuleResult && !idsLoading && (
                <div className="flex flex-col gap-5">
                  {/* Rule Header Metadata Card */}
                  <div className="bg-slate-950 border border-slate-800 rounded-xl p-4 flex flex-col gap-3">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${
                          idsRuleResult.threatSeverity.toLowerCase() === 'critical' ? 'bg-red-500/15 border border-red-500/30 text-red-400' :
                          idsRuleResult.threatSeverity.toLowerCase() === 'high' ? 'bg-orange-500/15 border border-orange-500/30 text-orange-400' :
                          'bg-amber-500/15 border border-amber-500/30 text-amber-400'
                        }`}>
                          {idsRuleResult.threatSeverity} Severity
                        </span>
                        {idsRuleResult.targetProtocol && (
                          <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-slate-900 border border-slate-800 text-slate-300">
                            Protocol: {idsRuleResult.targetProtocol}
                          </span>
                        )}
                        {idsRuleResult.mitreAttackMapping && (
                          <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-purple-500/10 border border-purple-500/20 text-purple-300">
                            MITRE ATT&CK: {idsRuleResult.mitreAttackMapping}
                          </span>
                        )}
                      </div>
                      <button
                        type="button"
                        onClick={copyAllRules}
                        className="flex items-center gap-1.5 px-2.5 py-1 bg-slate-900 hover:bg-slate-850 border border-slate-800 text-slate-300 hover:text-white rounded text-xs font-semibold transition-all cursor-pointer"
                      >
                        {copiedAllRules ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5 text-slate-400" />}
                        <span>{copiedAllRules ? 'All Copied!' : 'Copy Both Rules'}</span>
                      </button>
                    </div>

                    <h4 className="text-sm font-bold text-white">
                      {idsRuleResult.ruleTitle}
                    </h4>

                    <p className="text-xs text-slate-400 leading-relaxed">
                      {idsRuleResult.signatureExplanation}
                    </p>
                  </div>

                  {/* Forensic Layer Breakdown Pill Grid */}
                  {idsRuleResult.layerBreakdown && (
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-2.5 text-xs font-mono">
                      <div className="bg-slate-950/80 border border-slate-850 rounded-lg p-2.5">
                        <span className="text-[10px] uppercase font-bold text-cyan-400 block mb-1">Layer 3 Network Target</span>
                        <span className="text-slate-300 text-[11px] leading-relaxed break-words">{idsRuleResult.layerBreakdown.l3}</span>
                      </div>
                      <div className="bg-slate-950/80 border border-slate-850 rounded-lg p-2.5">
                        <span className="text-[10px] uppercase font-bold text-blue-400 block mb-1">Layer 4 Transport Filter</span>
                        <span className="text-slate-300 text-[11px] leading-relaxed break-words">{idsRuleResult.layerBreakdown.l4}</span>
                      </div>
                      <div className="bg-slate-950/80 border border-slate-850 rounded-lg p-2.5">
                        <span className="text-[10px] uppercase font-bold text-emerald-400 block mb-1">Layer 7 Signature Payload</span>
                        <span className="text-slate-300 text-[11px] leading-relaxed break-words truncate block">{idsRuleResult.layerBreakdown.l7}</span>
                      </div>
                    </div>
                  )}

                  {/* 1. Suricata IDS Rule Code Block (st.code equivalent) */}
                  <div className="bg-slate-950 border border-slate-800 rounded-xl overflow-hidden flex flex-col">
                    <div className="flex items-center justify-between px-4 py-2.5 bg-slate-900/60 border-b border-slate-800">
                      <div className="flex items-center gap-2">
                        <Code className="h-3.5 w-3.5 text-cyan-400" />
                        <span className="text-xs font-bold text-slate-200">Suricata IDS Rule</span>
                        <span className="text-[10px] font-mono text-slate-500 bg-slate-900 px-1.5 py-0.5 rounded border border-slate-800">
                          rules/autotac_threat.rules
                        </span>
                      </div>
                      <div className="flex items-center gap-2">
                        <button
                          type="button"
                          onClick={() => downloadFile('autotac_threat.rules', idsRuleResult.suricataRule, 'text/plain')}
                          className="flex items-center gap-1 px-2 py-1 text-[11px] font-medium text-slate-400 hover:text-slate-200 hover:bg-slate-850 rounded transition-colors"
                          title="Download .rules file"
                        >
                          <Download className="h-3 w-3" />
                          <span>.rules</span>
                        </button>
                        <button
                          type="button"
                          onClick={copySuricataRule}
                          className="flex items-center gap-1.5 px-2.5 py-1 bg-cyan-500/10 hover:bg-cyan-500/20 border border-cyan-500/30 text-cyan-300 rounded text-xs font-semibold transition-all cursor-pointer"
                        >
                          {copiedSuricata ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
                          <span>{copiedSuricata ? 'Copied Suricata!' : 'Copy Suricata Rule'}</span>
                        </button>
                      </div>
                    </div>

                    {/* Streamlit style code display container */}
                    <div className="p-4 bg-slate-950 font-mono text-[11px] text-cyan-300 overflow-x-auto select-all leading-relaxed whitespace-pre-wrap border-l-2 border-l-cyan-500">
                      <code>{idsRuleResult.suricataRule}</code>
                    </div>
                  </div>

                  {/* 2. SIEM Sigma Rule Code Block (st.code equivalent) */}
                  <div className="bg-slate-950 border border-slate-800 rounded-xl overflow-hidden flex flex-col">
                    <div className="flex items-center justify-between px-4 py-2.5 bg-slate-900/60 border-b border-slate-800">
                      <div className="flex items-center gap-2">
                        <FileCode className="h-3.5 w-3.5 text-purple-400" />
                        <span className="text-xs font-bold text-slate-200">SIEM Sigma Detection Rule</span>
                        <span className="text-[10px] font-mono text-slate-500 bg-slate-900 px-1.5 py-0.5 rounded border border-slate-800">
                          detections/network_threat.yml
                        </span>
                      </div>
                      <div className="flex items-center gap-2">
                        <button
                          type="button"
                          onClick={() => downloadFile('network_threat.yml', idsRuleResult.sigmaRule, 'text/yaml')}
                          className="flex items-center gap-1 px-2 py-1 text-[11px] font-medium text-slate-400 hover:text-slate-200 hover:bg-slate-850 rounded transition-colors"
                          title="Download .yml file"
                        >
                          <Download className="h-3 w-3" />
                          <span>.yml</span>
                        </button>
                        <button
                          type="button"
                          onClick={copySigmaRule}
                          className="flex items-center gap-1.5 px-2.5 py-1 bg-purple-500/10 hover:bg-purple-500/20 border border-purple-500/30 text-purple-300 rounded text-xs font-semibold transition-all cursor-pointer"
                        >
                          {copiedSigma ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
                          <span>{copiedSigma ? 'Copied Sigma!' : 'Copy Sigma Rule'}</span>
                        </button>
                      </div>
                    </div>

                    {/* Streamlit style code display container */}
                    <div className="p-4 bg-slate-950 font-mono text-[11px] text-purple-300 overflow-x-auto select-all leading-relaxed whitespace-pre border-l-2 border-l-purple-500 max-h-72">
                      <code>{idsRuleResult.sigmaRule}</code>
                    </div>
                  </div>
                </div>
              )}
            </div>

            {/* Modal Footer */}
            <div className="flex items-center justify-between px-6 py-3 border-t border-slate-800 bg-slate-950/60">
              <span className="text-[11px] text-slate-500">
                Copy directly to Suricata firewall ruleset or SIEM pipeline (Elastic / Splunk / QRadar)
              </span>
              <button
                type="button"
                onClick={() => setIdsModalOpen(false)}
                className="px-4 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold rounded-lg transition-colors cursor-pointer"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
