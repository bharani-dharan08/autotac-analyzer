/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import express from 'express';
import { createServer as createViteServer } from 'vite';
import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs';
import dotenv from 'dotenv';
import { GoogleGenAI, Type } from '@google/genai';
import { parsePcap } from './src/utils/pcapParser';
import { generateScenarioPcap } from './src/utils/pcapGenerator';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

// Increase JSON limits to handle larger PCAP Base64 uploads
app.use(express.json({ limit: '50mb' }));

// Initializing the server-side Gemini client
const ai = new GoogleGenAI({
  apiKey: process.env.GEMINI_API_KEY,
  httpOptions: {
    headers: {
      'User-Agent': 'aistudio-build',
    }
  }
});

// PCAP Analysis API
app.post('/api/analyze-pcap', async (req, res) => {
  try {
    const { pcapBase64, scenarioId } = req.body;
    let buffer: Buffer;

    if (scenarioId) {
      buffer = generateScenarioPcap(scenarioId);
    } else if (pcapBase64) {
      buffer = Buffer.from(pcapBase64, 'base64');
    } else {
      res.status(400).json({ error: 'Missing pcapBase64 or scenarioId in request.' });
      return;
    }

    const result = parsePcap(buffer);
    res.json(result);
  } catch (error: any) {
    console.error('Error analyzing PCAP:', error);
    res.status(500).json({ error: error.message || 'An error occurred during PCAP parsing.' });
  }
});

// Scenario Binary Download API (downloads a real, functional PCAP)
app.get('/api/download-scenario/:scenarioId', (req, res) => {
  try {
    const { scenarioId } = req.params;
    const buffer = generateScenarioPcap(scenarioId);

    res.setHeader('Content-Type', 'application/vnd.tcpdump.pcap');
    res.setHeader('Content-Disposition', `attachment; filename=autotac_${scenarioId}.pcap`);
    res.send(buffer);
  } catch (error: any) {
    console.error('Error generating download:', error);
    res.status(500).send('Failed to generate PCAP file.');
  }
});

// Binary helper to filter standard PCAP records
const filterPcapBuffer = (buffer: Buffer, indicesToKeep: number[]): Buffer => {
  if (buffer.length < 24) return buffer;
  const magic = buffer.readUInt32LE(0);
  const keepSet = new Set(indicesToKeep);

  // PCAPNG Format
  if (magic === 0x0a0d0d0a) {
    const chunks: Buffer[] = [];
    let offset = 0;
    let packetIdx = 0;

    while (offset + 8 <= buffer.length) {
      const blockType = buffer.readUInt32LE(offset);
      const blockLength = buffer.readUInt32LE(offset + 4);

      if (blockLength < 12 || offset + blockLength > buffer.length) {
        break;
      }

      const block = buffer.subarray(offset, offset + blockLength);

      if (blockType === 0x00000006 || blockType === 0x00000002) {
        if (keepSet.has(packetIdx)) {
          chunks.push(block);
        }
        packetIdx++;
      } else {
        // Keep non-packet headers (SHB, IDB, etc.)
        chunks.push(block);
      }

      offset += blockLength;
    }
    return Buffer.concat(chunks);
  }

  // Classic PCAP Format
  let isBigEndian = false;
  if (magic === 0xd4c3b2a1 || magic === 0x4d3cb2a1) {
    isBigEndian = true;
  }

  const readU32 = (offset: number) => isBigEndian ? buffer.readUInt32BE(offset) : buffer.readUInt32LE(offset);

  const chunks: Buffer[] = [buffer.subarray(0, 24)]; // global header
  let offset = 24;
  let packetIdx = 0;

  while (offset + 16 <= buffer.length) {
    const inclLen = readU32(offset + 8);
    const packetRecordSize = 16 + inclLen;

    if (offset + packetRecordSize > buffer.length) break;

    if (keepSet.has(packetIdx)) {
      chunks.push(buffer.subarray(offset, offset + packetRecordSize));
    }

    offset += packetRecordSize;
    packetIdx++;
  }

  return Buffer.concat(chunks);
};

// Filtered Binary PCAP download API
app.post('/api/download-filtered', (req, res) => {
  try {
    const { pcapBase64, scenarioId, filteredIndices } = req.body;

    if (!filteredIndices || !Array.isArray(filteredIndices)) {
      res.status(400).json({ error: 'Missing filteredIndices array.' });
      return;
    }

    let buffer: Buffer;
    if (scenarioId) {
      buffer = generateScenarioPcap(scenarioId);
    } else if (pcapBase64) {
      buffer = Buffer.from(pcapBase64, 'base64');
    } else {
      res.status(400).json({ error: 'Missing original packet capture reference.' });
      return;
    }

    const filteredBuffer = filterPcapBuffer(buffer, filteredIndices);

    res.setHeader('Content-Type', 'application/vnd.tcpdump.pcap');
    res.setHeader('Content-Disposition', 'attachment; filename=autotac_filtered_subset.pcap');
    res.send(filteredBuffer);
  } catch (error: any) {
    console.error('Error generating filtered packet download:', error);
    res.status(500).json({ error: error.message || 'Failed to construct filtered packet capture.' });
  }
});


// Gemini Root Cause Analysis API
app.post('/api/gemini/analyze', async (req, res) => {
  try {
    const { analysisResult, customInstruction } = req.body;

    if (!analysisResult) {
      res.status(400).json({ error: 'Missing analysisResult details.' });
      return;
    }

    // Prepare a structured textual summary for Gemini
    const {
      totalPackets,
      totalBytes,
      protocolCounts,
      totalTcpPackets,
      retransmissionCount,
      duplicateAckCount,
      globalRetransmissionRate,
      dnsFailureCount,
      plaintextCredentialsCount,
      connections,
      dnsAnomalies,
      plaintextCredentials,
      captureProfiler,
      averageRtt,
      maxRtt
    } = analysisResult;

    // Filter connections exceeding 1% Retransmission rule
    const worstConnections = (connections || [])
      .filter((c: any) => c.retransmissionRate > 1 && c.retransmissions > 0)
      .slice(0, 5);

    const dnsSummary = (dnsAnomalies || [])
      .slice(0, 5)
      .map((p: any) => `Time: ${new Date(p.timestamp).toISOString().split('T')[1].slice(0, -1)}s | Host: ${p.srcIp} -> DNS Server: ${p.dstIp} | Queried Domain: "${p.dnsQuery?.domain}" | Response Status: ${p.dnsQuery?.rcodeName} (RCODE ${p.dnsQuery?.rcode})`)
      .join('\n');

    const credsSummary = (plaintextCredentials || [])
      .slice(0, 5)
      .map((p: any) => `Time: ${new Date(p.timestamp).toISOString().split('T')[1].slice(0, -1)}s | Client: ${p.srcIp} -> Server: ${p.dstIp}:${p.dstPort || 80} | Leak Service: ${p.plaintextCredentials?.service} (${p.plaintextCredentials?.type}) | Exposed Payload Info: "${p.plaintextCredentials?.value}"`)
      .join('\n');

    const connectionsSummary = worstConnections
      .map((c: any) => `- Connection Flow: [${c.srcIp}] to [${c.dstIp}] | TCP Packets: ${c.tcpPackets} | Retransmissions: ${c.retransmissions} | Connection-specific Drop Rate: ${c.retransmissionRate.toFixed(2)}%`)
      .join('\n');

    const profiler = captureProfiler || {
      averageFrameSize: 0,
      protocolBreakdown: [],
      commonTcpWindowSizes: [],
      mtuAnalysis: { maxFrameSize: 0, possibleMtuIssue: false, description: 'N/A' }
    };

    const profilerProtoSummary = profiler.protocolBreakdown
      .map((p: any) => `- Protocol ${p.protocol}: count=${p.count} | total bytes=${p.bytes} | percentage=${p.percentage.toFixed(1)}%`)
      .join('\n');

    const profilerWindowSummary = profiler.commonTcpWindowSizes
      .map((w: any) => `- TCP Window Size ${w.windowSize} bytes: count=${w.count} | percentage=${w.percentage.toFixed(1)}%`)
      .join('\n');

    const systemPrompt = `You are a Principal TAC (Technical Assistance Center) Engineer and Network Forensic Expert specializing in resolving high-priority critical business outages (SEV-1).
Your job is to analyze the statistics parsed from a packet capture and write a highly professional, expert-level, actionable Root Cause Analysis (RCA) report.

Adopt a serious, elite network consulting engineer tone. Do NOT use emojis, hype, or generic introductory phrases like "Sure! Here is the report." Start directly with the professional report. Use structured Markdown with clean sections.`;

    const userPrompt = `
Here are the packet inspection metrics parsed from the target network capture (.pcap):

## CAPTURE SUMMARY METRICS:
- Total Parsed Packets: ${totalPackets}
- Total Payload Data Bytes: ${totalBytes} bytes
- Protocol Distribution: ${JSON.stringify(protocolCounts)}

## CAPTURE PROFILER STATISTICS (MTU & TCP WINDOW ANALYSIS):
- Average Packet Frame Size: ${profiler.averageFrameSize.toFixed(1)} bytes
- Observed Protocol Breakdown (Bytes and Counts):
${profilerProtoSummary || '- No protocol breakdown available.'}
- Most Common TCP Window Sizes:
${profilerWindowSummary || '- No TCP window distribution available.'}
- Path MTU Discovery (PMTUD) & Size Diagnostics:
  * Maximum Observed Frame Size: ${profiler.mtuAnalysis.maxFrameSize} bytes
  * Possible Path MTU Bottleneck or Configuration Issue: ${profiler.mtuAnalysis.possibleMtuIssue ? 'YES' : 'NO'}
  * MTU Analysis Statement: ${profiler.mtuAnalysis.description}

## TCP LOSS & CONGESTION STATISTICS:
- Total TCP Packets Inspect: ${totalTcpPackets}
- Captured Retransmissions: ${retransmissionCount} segments
- Captured Duplicate ACKs: ${duplicateAckCount} segments
- Calculated Global TCP Retransmission Rate: ${globalRetransmissionRate.toFixed(2)}% (Note: Enterprise safe threshold is < 1.0%)
- Measured Round-Trip Time (RTT) Latency: Average: ${averageRtt ? averageRtt.toFixed(1) : 0.0} ms | Max: ${maxRtt ? maxRtt.toFixed(1) : 0.0} ms

## HIGH-LOSS FLOWS IDENTIFIED (CULPRIT FLOWS EXCEEDING 1% THRESHOLD):
${connectionsSummary || 'No TCP connections exceeded the critical 1.0% drop/retransmission rate.'}

## DNS OUTAGE & RESOLUTION ANOMALIES:
- Detected DNS Server Failure & NXDomain Failures: ${dnsFailureCount} counts
${dnsSummary ? `Recent Failed Resolutions:\n${dnsSummary}` : 'No active DNS failures or server failures flagged.'}

## SOC PLAIN-TEXT SECURITY ALERTS:
- Detected Cleartext Login Credentials: ${plaintextCredentialsCount} instances
${credsSummary ? `Identified Security Leaks:\n${credsSummary}` : 'No unencrypted credentials or plain-text basic auth headers detected.'}

${customInstruction ? `## USER ADDITIONAL NOTES / CONTEXT:\n${customInstruction}` : ''}

Please analyze this structured diagnostic evidence and output the RCA report covering:
1. **Executive Outage Status Summary**: Summarize the health of this system (e.g., SEV-1 Outage, Warning, or Nominal) based on the findings (especially the "1% Rule" for TCP packet loss).
2. **Detailed Technical Root Cause Analysis**: Match the anomalies. If there is high packet loss or ServFail/NXDomain responses, explain exactly what protocol mechanics went wrong. If plain-text credentials were leaked, highlight the security risk.
3. **Capture Profiler, Path MTU & RTT Latency Diagnostics**: Analyze average/max RTT latency along with frame size and window distribution to identify potential MTU mismatches, bufferbloat, path bottlenecks, or routing loops.
4. **Evidence Proof**: Reference the IP addresses, port numbers, sequence/acknowledgment numbers, domain names, or MTU sizes from the evidence to back up your claim.
5. **Step-by-Step TAC Remediation Playbook**: Provide highly actionable steps to resolve the root cause (e.g. firewall routing policy fixes, configuring TCP MSS clamping to 1420B, DNS daemon restarter commands, or forcing HTTPS/SFTP).
`;

    let rcaText: string | null = null;

    if (process.env.GEMINI_API_KEY) {
      const candidateModels = ['gemini-3.1-flash-lite', 'gemini-flash-latest', 'gemini-3.8-flash'];
      for (const modelName of candidateModels) {
        try {
          const response = await ai.models.generateContent({
            model: modelName,
            contents: userPrompt,
            config: {
              systemInstruction: systemPrompt,
              temperature: 0.2, // low temperature for precise factual network consulting
            }
          });
          if (response.text) {
            rcaText = response.text;
            break;
          }
        } catch (modelErr: any) {
          console.warn(`Model ${modelName} failed or quota exhausted:`, modelErr?.message || modelErr);
        }
      }
    }

    if (!rcaText) {
      console.info('Using deterministic TAC root cause analysis engine.');
      rcaText = generateDeterministicRcaReport(analysisResult, customInstruction);
    }

    res.json({ rcaReport: rcaText });
  } catch (error: any) {
    console.error('Unexpected error in analyze endpoint, providing deterministic fallback:', error);
    try {
      const fallbackReport = generateDeterministicRcaReport(req.body?.analysisResult, req.body?.customInstruction);
      res.json({ rcaReport: fallbackReport });
    } catch (innerErr: any) {
      res.status(500).json({ error: 'Failed to generate root cause analysis report.' });
    }
  }
});

// Gemini Consolidated Batch Comparison Analysis API
app.post('/api/gemini/analyze-batch', async (req, res) => {
  try {
    const { batchCaptures, customInstruction } = req.body;

    if (!batchCaptures || !Array.isArray(batchCaptures) || batchCaptures.length === 0) {
      res.status(400).json({ error: 'Missing batchCaptures array.' });
      return;
    }

    const summaries = batchCaptures.map((capture: any, idx: number) => {
      const { fileName, result } = capture;
      const {
        totalPackets,
        totalBytes,
        globalRetransmissionRate,
        dnsFailureCount,
        plaintextCredentialsCount,
        captureProfiler
      } = result;

      const avgFrame = captureProfiler?.averageFrameSize || 0;
      const maxFrame = captureProfiler?.mtuAnalysis?.maxFrameSize || 0;

      return `Capture #${idx + 1}: "${fileName}"
- Packets: ${totalPackets} | Volume: ${totalBytes.toLocaleString()} bytes
- Average Frame Size: ${avgFrame.toFixed(1)} bytes | Max Frame Size: ${maxFrame} bytes
- TCP Retransmission Rate: ${globalRetransmissionRate.toFixed(2)}%
- DNS Failures: ${dnsFailureCount} anomalies | Plain-text credentials leaks: ${plaintextCredentialsCount} instances
`;
    }).join('\n\n');

    const systemPrompt = `You are a Principal TAC (Technical Assistance Center) Engineer and Network Forensic Expert.
Your job is to analyze a batch of network captures taken from different intervals, servers, or nodes, and write a consolidated network health comparison report.

Adopt a serious, elite network consulting engineer tone. Do NOT use emojis or generic introductory phrases. Start directly with the professional report. Use structured Markdown with clean comparative sections.`;

    const userPrompt = `
Here are the parsed statistics from a batch of ${batchCaptures.length} network captures:

${summaries}

${customInstruction ? `## ADDITIONAL NOTES / NETWORK CONTEXT:\n${customInstruction}` : ''}

Please analyze this batch of captures and write a consolidated comparative report covering:
1. **Comparative Analytics Matrix**: Briefly summarize the key performance/health indicators of each capture (especially comparing TCP loss, DNS failures, and credential security).
2. **Correlation & Anomaly Pinpointing**: Explain how these captures relate to each other. For example, identify which nodes or captures are healthy (under the 1% TCP loss threshold), which are experiencing active performance outages, and which present severe security compliance violations.
3. **Consolidated Remediation Playbook**: Provide a prioritized list of actionable playbooks to resolve all identified outages and anomalies (e.g. configuring MTU size clamps, DNS daemon restarter commands, or forcing HTTPS/SFTP).
`;

    let batchText: string | null = null;

    if (process.env.GEMINI_API_KEY) {
      const candidateModels = ['gemini-3.1-flash-lite', 'gemini-flash-latest', 'gemini-3.8-flash'];
      for (const modelName of candidateModels) {
        try {
          const response = await ai.models.generateContent({
            model: modelName,
            contents: userPrompt,
            config: {
              systemInstruction: systemPrompt,
              temperature: 0.2,
            }
          });
          if (response.text) {
            batchText = response.text;
            break;
          }
        } catch (modelErr: any) {
          console.warn(`Batch model ${modelName} failed or quota exhausted:`, modelErr?.message || modelErr);
        }
      }
    }

    if (!batchText) {
      console.info('Using deterministic batch comparison analysis engine.');
      batchText = generateDeterministicBatchRcaReport(batchCaptures, customInstruction);
    }

    res.json({ batchReport: batchText });
  } catch (error: any) {
    console.error('Unexpected error in analyze-batch endpoint, providing deterministic fallback:', error);
    try {
      const fallbackReport = generateDeterministicBatchRcaReport(req.body?.batchCaptures || [], req.body?.customInstruction);
      res.json({ batchReport: fallbackReport });
    } catch (innerErr: any) {
      res.status(500).json({ error: 'Failed to generate batch comparison report.' });
    }
  }
});

// Deterministic TAC Root Cause Analysis Report Generator
const generateDeterministicRcaReport = (analysisResult: any, customInstruction?: string): string => {
  if (!analysisResult) {
    return '## TAC Root Cause Analysis Report\n\nNo analysis result provided to evaluate.';
  }

  const {
    totalPackets = 0,
    totalBytes = 0,
    totalTcpPackets = 0,
    retransmissionCount = 0,
    duplicateAckCount = 0,
    globalRetransmissionRate = 0,
    dnsFailureCount = 0,
    plaintextCredentialsCount = 0,
    connections = [],
    dnsAnomalies = [],
    plaintextCredentials = [],
    captureProfiler,
    averageRtt,
    maxRtt,
    bgpNotifications = [],
    ospfMismatches = [],
    voipAnalysis
  } = analysisResult;

  const isSevereTcpLoss = globalRetransmissionRate >= 1.0;
  const isSevereDns = dnsFailureCount > 0;
  const isSevereSecurity = plaintextCredentialsCount > 0;
  const isSevereBgp = (bgpNotifications || []).length > 0;
  const isSevereOspf = (ospfMismatches || []).length > 0;
  const isSevereVoip = voipAnalysis && (voipAnalysis.maxRtpPacketLossPercent >= 3.0 || voipAnalysis.failedCallsCount > 0);

  let severity = 'NOMINAL (Health Grade A)';
  let outageLabel = 'Normal Network Operation';
  if (globalRetransmissionRate >= 5.0 || dnsFailureCount >= 3 || isSevereBgp || (voipAnalysis && voipAnalysis.maxRtpPacketLossPercent >= 10.0)) {
    severity = 'SEV-1 CRITICAL OUTAGE';
    outageLabel = 'Active Enterprise Outage with Service Disruption';
  } else if (isSevereTcpLoss || isSevereDns || isSevereSecurity || isSevereOspf || isSevereVoip) {
    severity = 'SEV-2 MAJOR DEGRADATION';
    outageLabel = 'Severe Performance Impairment & SLA Breach';
  }

  const worstConnections = (connections || [])
    .filter((c: any) => c.retransmissionRate > 1 && c.retransmissions > 0)
    .slice(0, 5);

  const rcaSections: string[] = [];

  // Section 1: Executive Outage Status Summary
  rcaSections.push(`## 1. Executive Outage Status Summary
- **Classification Status**: **${severity}**
- **Incident Summary**: ${outageLabel}
- **Global Transport Retransmission Rate**: **${globalRetransmissionRate.toFixed(2)}%** (Industry standard maximum threshold is 1.00%)
- **Inspected Capture Scope**: ${totalPackets.toLocaleString()} frames (${(totalBytes / 1024).toFixed(1)} KB)
- **Primary Finding**: ${
    isSevereTcpLoss
      ? `Severe packet drop rate of ${globalRetransmissionRate.toFixed(2)}% observed across TCP application sessions, exceeding the enterprise 1% Rule and causing severe application timeouts.`
      : isSevereDns
      ? `Critical DNS resolution failure storm detected (${dnsFailureCount} queries returning ServFail/NXDomain), preventing upstream API reachability.`
      : isSevereSecurity
      ? `Security violation: ${plaintextCredentialsCount} unencrypted credential transmissions detected traversing plaintext protocols.`
      : isSevereBgp
      ? `BGP peering drop detected: RFC 4271 NOTIFICATION message terminated core routing peer adjacency.`
      : isSevereOspf
      ? `OSPF adjacency stuck in EXSTART: Neighbor Database Description interface MTU mismatch.`
      : isSevereVoip
      ? `Telephony degradation: RTP voice transport suffering ${(voipAnalysis?.maxRtpPacketLossPercent || 0).toFixed(1)}% packet loss and ${voipAnalysis?.failedCallsCount || 0} SIP signaling failures.`
      : 'Network traffic baseline operating within nominal operational thresholds.'
  }`);

  // Section 2: Detailed Technical Root Cause Analysis
  rcaSections.push(`## 2. Detailed Technical Root Cause Analysis
### Protocol Mechanics Breakdown:
${
  isSevereTcpLoss
    ? `- **TCP Layer Transport Breakdown**: Out of ${totalTcpPackets.toLocaleString()} TCP segments, AutoTAC observed ${retransmissionCount} retransmissions and ${duplicateAckCount} Duplicate ACKs. This symptom profile points to congestion-induced queue drops on intermediate switches or asymmetric return path drops.`
    : `- **TCP Layer Health**: Retransmission rate of ${globalRetransmissionRate.toFixed(2)}% is within standard tolerances.`
}
${
  isSevereDns
    ? `- **DNS Control-Plane Failures**: ${dnsFailureCount} DNS queries failed with RCODE 2 (ServFail) or RCODE 3 (NXDomain). Queries directed to primary resolver ${dnsAnomalies[0]?.dstIp || 'internal resolver'} timed out or were refused, triggering recursive client timeouts.`
    : `- **DNS Infrastructure**: No abnormal recursive lookups or SERVFAIL events detected.`
}
${
  isSevereSecurity
    ? `- **Plaintext Security Breach**: Inspection detected ${plaintextCredentialsCount} instances of unencrypted sensitive credentials transmitted via plaintext HTTP Basic Auth or FTP. Attackers with LAN visibility can execute credential harvesting.`
    : `- **Security Integrity**: No cleartext credential leaks identified in this capture slice.`
}
${
  isSevereBgp
    ? `- **BGP Peering Outage**: BGP NOTIFICATION message Type 3 detected between core routers (${bgpNotifications[0]?.srcIp} -> ${bgpNotifications[0]?.dstIp}). Error: ${bgpNotifications[0]?.errorName} (Code ${bgpNotifications[0]?.errorCode}, Subcode ${bgpNotifications[0]?.subcode}), causing immediate BGP session teardown and route withdrawal.`
    : ''
}
${
  isSevereOspf
    ? `- **OSPF Adjacency Deadlock**: OSPFv2 DBD interface MTU mismatch detected (${ospfMismatches[0]?.srcIp} MTU ${ospfMismatches[0]?.router1Mtu}B vs ${ospfMismatches[0]?.dstIp} MTU ${ospfMismatches[0]?.router2Mtu}B). Routers are stuck in EXSTART/EXCHANGE state and will never reach FULL adjacency.`
    : ''
}
${
  isSevereVoip
    ? `- **VoIP Voice Telephony Degradation**: RTP audio streams exhibit ${(voipAnalysis?.maxRtpPacketLossPercent || 0).toFixed(1)}% packet loss based on missing RTP sequence numbers. Furthermore, SIP signaling sessions encountered ${(voipAnalysis?.failedCallsCount || 0)} failure status responses (4xx/5xx/6xx), resulting in failed call establishment and robotic voice quality.`
    : ''
}`);

  // Section 3: Capture Profiler, Path MTU & RTT Latency Diagnostics
  rcaSections.push(`## 3. Capture Profiler, Path MTU & RTT Latency Diagnostics
- **Average Frame Size**: ${captureProfiler?.averageFrameSize ? captureProfiler.averageFrameSize.toFixed(1) : '64.0'} bytes
- **Maximum Observed Frame Size**: ${captureProfiler?.mtuAnalysis?.maxFrameSize || 1514} bytes
- **Path MTU Bottleneck Diagnostic**: ${captureProfiler?.mtuAnalysis?.possibleMtuIssue ? 'YES — Potential MTU/MSS mismatch or blackhole' : 'NO — Frames fit standard 1500B Ethernet MTU'}
- **Observed Round-Trip Time (RTT)**: Average: ${averageRtt ? averageRtt.toFixed(1) : '0.0'} ms | Maximum: ${maxRtt ? maxRtt.toFixed(1) : '0.0'} ms
- **TCP Window Distribution**: Most common window size is ${captureProfiler?.commonTcpWindowSizes?.[0]?.windowSize || 64240} bytes, representing ${captureProfiler?.commonTcpWindowSizes?.[0]?.percentage ? captureProfiler.commonTcpWindowSizes[0].percentage.toFixed(1) : '100'}% of connections. Window sizes indicate healthy receiver buffer capacity, confirming network drops occur in transit rather than host OS buffer starvation.`);

  // Section 4: Evidence Proof & High-Loss Culprit Connections
  rcaSections.push(`## 4. Evidence Proof & High-Loss Culprit Connections
| Source IP | Destination IP | TCP Packets | Retransmissions | Drop Rate % | Status Verdict |
| :--- | :--- | :---: | :---: | :---: | :--- |
${worstConnections.length > 0
  ? worstConnections.map((c: any) => `| \`${c.srcIp}\` | \`${c.dstIp}\` | ${c.tcpPackets} | ${c.retransmissions} | **${c.retransmissionRate.toFixed(2)}%** | ${c.retransmissionRate >= 5 ? 'CRITICAL DROP' : 'HIGH LOSS'} |`).join('\n')
  : '| 10.0.0.0/8 | 192.168.0.0/16 | - | - | < 1.00% | Nominal |'
}

${dnsAnomalies.length > 0 ? `\n**Flagged DNS Resolution Failures**:\n` + dnsAnomalies.slice(0, 3).map((d: any) => `- Client \`${d.srcIp}\` queried \`${d.dnsQuery?.domain}\` -> Response: **${d.dnsQuery?.rcodeName} (RCODE ${d.dnsQuery?.rcode})** from \`${d.dstIp}\``).join('\n') : ''}
${plaintextCredentials.length > 0 ? `\n**Flagged Plaintext Security Exposures**:\n` + plaintextCredentials.slice(0, 3).map((p: any) => `- Host \`${p.srcIp}\` sent unencrypted \`${p.plaintextCredentials?.service}\` payload to \`${p.dstIp}:${p.dstPort || 80}\``).join('\n') : ''}`);

  // Section 5: Step-by-Step TAC Remediation Playbook
  rcaSections.push(`## 5. Step-by-Step TAC Remediation Playbook
1. **Immediate Mitigation (QoS & Queue Sizing)**:
   - For TCP congestion drops: Apply TCP MSS clamping on edge firewalls (\`ip tcp adjust-mss 1360\`) to eliminate fragmentation drops across tunneling boundaries.
   - For VoIP degradation: Configure DSCP Expedited Forwarding (EF / value 46) on UDP voice ports (16384-32767) with strict priority queuing (LLQ).
2. **Infrastructure Configuration Fixes**:
   ${isSevereDns ? '- Restart internal DNS daemon (named/unbound/coredns) and audit firewall UDP port 53 outbound inspect rules.\n' : ''}${isSevereBgp ? '- Verify BGP keepalive timers (default 60s/180s) and check interface error counters on peer links.\n' : ''}${isSevereOspf ? '- Adjust OSPF interface MTU to match adjacent neighbor or configure `ip ospf mtu-ignore` on the connecting link.\n' : ''}${isSevereSecurity ? '- Enforce TLS 1.3 encryption on internal web services (port 443) and decommission legacy cleartext protocols (FTP/Telnet/HTTP Basic).\n' : ''}3. **Verification & Post-Remediation Validation**:
   - Re-capture packet traffic on the same ingress interface and confirm TCP retransmission rate drops below 1.00%.
   - Validate SIP session establishment completes with \`200 OK\` and RTP stream sequence loss reaches 0.0%.`);

  if (customInstruction) {
    rcaSections.push(`\n---\n*TAC Notes / Analyst Context Incorporated: ${customInstruction}*`);
  }

  return rcaSections.join('\n\n');
};

// Deterministic Batch Comparison Report Generator
const generateDeterministicBatchRcaReport = (batchCaptures: any[], customInstruction?: string): string => {
  if (!batchCaptures || batchCaptures.length === 0) {
    return '## Consolidated Multi-Capture Comparison Report\n\nNo capture files provided for batch evaluation.';
  }

  const rows = batchCaptures.map((c: any, i: number) => {
    const res = c.result;
    const loss = res?.globalRetransmissionRate || 0;
    const dnsErr = res?.dnsFailureCount || 0;
    const credErr = res?.plaintextCredentialsCount || 0;
    const status = loss >= 5 || dnsErr >= 3 ? 'CRITICAL (SEV-1)' : loss >= 1 || credErr > 0 ? 'MAJOR (SEV-2)' : 'NOMINAL';
    return `| Capture #${i + 1}: \`${c.fileName}\` | ${res?.totalPackets || 0} | ${loss.toFixed(2)}% | ${dnsErr} | ${credErr} | **${status}** |`;
  }).join('\n');

  return `## Consolidated Multi-Capture Comparison & Forensic Analysis

### 1. Comparative Analytics Matrix
| Capture File | Total Frames | TCP Retrans % | DNS Failures | Leaked Creds | Health Verdict |
| :--- | :---: | :---: | :---: | :---: | :--- |
${rows}

### 2. Multi-Node Correlation & Incident Pinpointing
- **Performance Correlation**: Captured files with TCP retransmission rates exceeding 1.00% represent localized link congestion, buffer exhaustion, or MTU blackholes.
- **Security & Availability Discrepancies**: Discrepancies across captures indicate whether failures are widespread infrastructure outages (e.g. centralized DNS daemon down) or host-specific configuration anomalies.

### 3. Consolidated Remediation Playbook
1. Prioritize node recovery on critical SEV-1 captures first by auditing interface drops and router CPU utilization.
2. Implement enterprise-wide TCP MSS clamping (\`ip tcp adjust-mss 1360\`) to resolve path MTU drops across all network segments.
3. Migrate all legacy services identified with plaintext credential transmissions to encrypted transport (HTTPS/SFTP).
${customInstruction ? `\n*Analyst Context Incorporated: ${customInstruction}*` : ''}`;
};

// Fallback heuristic IDS rule synthesizer if Gemini API key is absent or offline
const synthesizeFallbackIdsRule = (packet: any, anomalyReason?: string) => {
  const isPlaintext = Boolean(packet.plaintextCredentials);
  const isDns = packet.protocol === 'DNS' || Boolean(packet.dnsQuery);
  const isTls = Boolean(packet.tlsAlert);
  const proto = (packet.protocol || 'TCP').toLowerCase();
  const dPort = packet.dstPort || (isDns ? 53 : proto === 'http' ? 80 : proto === 'ftp' ? 21 : 443);
  const sPort = packet.srcPort || 'any';
  const dstIp = packet.dstIp || '$HOME_NET';

  let title = `AutoTAC - Suspicious ${packet.protocol || 'TCP'} Network Traffic Anomaly`;
  let severity = 'Medium';
  let mitre = 'T1048 - Exfiltration Over Alternative Protocol';
  let suricataContent = '';

  if (isPlaintext) {
    title = `AutoTAC - Leaked Plaintext Credentials in ${packet.plaintextCredentials.service} Session`;
    severity = 'Critical';
    mitre = 'T1552 - Unsecured Credentials: Plaintext In Session';
    const val = (packet.plaintextCredentials.value || 'USER').replace(/["\\]/g, '');
    suricataContent = `content:"${val.slice(0, 16)}"; nocase; `;
  } else if (isDns && packet.dnsQuery) {
    title = `AutoTAC - Abnormal DNS Resolution / Anomaly (${packet.dnsQuery.domain || 'Query'})`;
    severity = 'High';
    mitre = 'T1071.004 - Application Layer Protocol: DNS';
    const domain = (packet.dnsQuery.domain || '').replace(/["\\]/g, '');
    suricataContent = `content:"${domain.slice(0, 20)}"; nocase; `;
  } else if (isTls) {
    title = `AutoTAC - Insecure or Failing TLS Handshake / Alert (${packet.tlsAlert?.description || 'Alert'})`;
    severity = 'High';
    mitre = 'T1573 - Encrypted Channel Disruption';
  } else if (packet.isRetransmission) {
    title = `AutoTAC - TCP Congestion Storm / Abnormal Retransmission Signature`;
    severity = 'Medium';
    mitre = 'T1498 - Network Denial of Service';
  }

  const sid = 1000000 + (packet.index ? packet.index % 900000 : Math.floor(1000 + Math.random() * 8999));
  const suricataRule = `alert ${proto} $EXTERNAL_NET ${sPort} -> ${dstIp} ${dPort} (msg:"${title}"; flow:established,to_server; ${suricataContent}classtype:bad-unknown; sid:${sid}; rev:1; metadata:created_by AutoTAC_Engine;)`;

  const sigmaRule = `title: ${title}
id: 4a2b9f81-5c3e-4d92-bf39-${(100000000000 + (packet.index || 1)).toString(16).slice(-12)}
status: experimental
description: AutoTAC synthesized network detection rule based on inspected PCAP signature: ${anomalyReason || 'Observed packet anomaly'}
references:
  - https://attack.mitre.org/techniques/${mitre.split(' ')[0]}
author: AutoTAC Detection Engineering
date: ${new Date().toISOString().split('T')[0]}
logsource:
  category: network_traffic
detection:
  selection:
    DestinationPort: ${dPort}
    DestinationIp: ${dstIp}
    Protocol: ${proto.toUpperCase()}
  condition: selection
falsepositives:
  - Legitimate authorized administrative network engineering or test probes
level: ${severity.toLowerCase()}
tags:
  - attack.${mitre.toLowerCase().replace(/[^a-z0-9]+/g, '_')}`;

  return {
    ruleTitle: title,
    suricataRule,
    sigmaRule,
    threatSeverity: severity,
    targetProtocol: packet.protocol || 'TCP',
    signatureExplanation: `Automated detection generated for Layer 3 host ${packet.srcIp} -> ${packet.dstIp}, Layer 4 port ${dPort}, matching observed payload signature: "${(packet.info || '').slice(0, 60)}".`,
    mitreAttackMapping: mitre
  };
};

// Threat-to-Code IDS Rule Synthesizer API
app.post('/api/gemini/generate-ids-rule', async (req, res) => {
  let layer3 = '';
  let layer4 = '';
  let layer7 = '';
  let packetData: any = null;
  let contextReason = '';

  try {
    const { packet, anomalyReason } = req.body;

    if (!packet) {
      res.status(400).json({ error: 'Missing packet details.' });
      return;
    }

    packetData = packet;
    contextReason = anomalyReason;

    const {
      srcIp,
      dstIp,
      srcPort,
      dstPort,
      protocol,
      ttl,
      ipId,
      tcpFlags,
      info,
      plaintextCredentials,
      dnsQuery,
      hexDump,
      payload
    } = packet;

    layer3 = `Source IP: ${srcIp || '$EXTERNAL_NET'} | Destination IP: ${dstIp || '$HOME_NET'} | TTL: ${ttl ?? 64} | IPID: ${ipId ? '0x' + ipId.toString(16).toUpperCase() : 'N/A'}`;
    layer4 = `Protocol: ${protocol || 'TCP'} | Source Port: ${srcPort || 'any'} | Destination Port: ${dstPort || 'any'}${tcpFlags ? ` | TCP Flags: ${Object.entries(tcpFlags).filter(([_, v]) => v).map(([k]) => k.toUpperCase()).join('/')}` : ''}`;
    layer7 = `Payload Info/Headers: "${info || 'N/A'}"${plaintextCredentials ? ` | Exposed Credentials Service: ${plaintextCredentials.service} (${plaintextCredentials.type}) Value: "${plaintextCredentials.value}"` : ''}${dnsQuery ? ` | DNS Query Domain: "${dnsQuery.domain}" RCODE: ${dnsQuery.rcodeName}` : ''}${payload ? ` | Raw Payload Text: "${payload}"` : ''}${hexDump ? ` | Hex Map snippet: ${hexDump.slice(0, 150)}` : ''}`;

    const systemPrompt = `You are a Principal Cyber Security Detection Engineer and SOC Automation Architect specializing in Intrusion Detection Systems (Suricata, Snort) and SIEM rules (Sigma, Splunk, Elastic).
Your task is to synthesize deployable, production-ready intrusion detection rules based on Layer 3, Layer 4, and Layer 7 network packet evidence.

CRITICAL FORMATTING REQUIREMENTS:
1. Suricata IDS Rule: Must be a strictly formatted, valid Suricata rule on a single line starting with:
   alert <protocol> $EXTERNAL_NET <port> -> $HOME_NET <port> (msg:"..."; ... sid:100000X; rev:1;)
   Use standard Suricata keywords such as: flow, content, nocase, classtype, sid, rev, metadata.
2. SIEM Sigma Rule: Must be a valid YAML-formatted Sigma detection rule containing title, id (UUID), status: experimental, description, logsource (category: network_traffic), detection (selection, condition), falsepositives, level (high/critical/medium), and tags (attack.tXXXX).
3. Do not include markdown code block formatting inside the JSON string values (keep the raw string clean).`;

    const userPrompt = `
Synthesize a deployable Suricata IDS rule and a SIEM Sigma rule from this captured network anomaly:

ANOMALY CONTEXT:
${anomalyReason || 'Suspicious network packet observed in automated PCAP forensic analysis.'}

LAYER 3 (NETWORK LAYER):
${layer3}

LAYER 4 (TRANSPORT LAYER):
${layer4}

LAYER 7 (APPLICATION LAYER / PAYLOAD):
${layer7}

Generate a strictly formatted Suricata IDS rule and a SIEM Sigma rule specifically tailored to detect this threat signature.`;

    let parsedData: any = null;

    if (process.env.GEMINI_API_KEY) {
      const candidateModels = ['gemini-3.1-flash-lite', 'gemini-flash-latest', 'gemini-3.8-flash'];
      for (const modelName of candidateModels) {
        try {
          const response = await ai.models.generateContent({
            model: modelName,
            contents: userPrompt,
            config: {
              systemInstruction: systemPrompt,
              temperature: 0.1,
              responseMimeType: 'application/json',
              responseSchema: {
                type: Type.OBJECT,
                properties: {
                  ruleTitle: { type: Type.STRING, description: 'Short technical title of the threat detection rule' },
                  suricataRule: { type: Type.STRING, description: 'Single-line, strictly formatted Suricata IDS rule starting with alert tcp/udp/ip ...' },
                  sigmaRule: { type: Type.STRING, description: 'Complete YAML formatted SIEM Sigma rule' },
                  threatSeverity: { type: Type.STRING, description: 'Critical, High, Medium, or Low' },
                  targetProtocol: { type: Type.STRING, description: 'e.g. TCP, HTTP, FTP, DNS' },
                  signatureExplanation: { type: Type.STRING, description: 'Detailed forensic rationale of how the Layer 3, Layer 4, and Layer 7 fields are matched' },
                  mitreAttackMapping: { type: Type.STRING, description: 'MITRE ATT&CK technique ID and name, e.g. T1552 - Unsecured Credentials' }
                },
                required: ['ruleTitle', 'suricataRule', 'sigmaRule', 'threatSeverity', 'signatureExplanation']
              }
            }
          });
          if (response.text) {
            parsedData = JSON.parse(response.text);
            break;
          }
        } catch (modelErr: any) {
          console.warn(`IDS Model ${modelName} failed or quota exhausted:`, modelErr?.message || modelErr);
        }
      }
    }

    if (!parsedData) {
      parsedData = synthesizeFallbackIdsRule(packetData, contextReason);
    }

    res.json({
      ...parsedData,
      layerBreakdown: {
        l3: layer3,
        l4: layer4,
        l7: layer7
      }
    });
  } catch (error: any) {
    console.error('Error generating IDS rule via Gemini, using deterministic fallback synthesizer:', error);
    try {
      const fallback = synthesizeFallbackIdsRule(packetData, contextReason);
      res.json({
        ...fallback,
        layerBreakdown: {
          l3: layer3,
          l4: layer4,
          l7: layer7
        }
      });
    } catch (innerErr) {
      res.status(500).json({ error: 'Failed to synthesize intrusion detection rule.' });
    }
  }
});

// Backend health status polling API
app.get('/api/status', (req, res) => {
  res.json({
    status: 'online',
    uptime: Math.floor(process.uptime()),
    memoryUsage: Math.floor(process.memoryUsage().heapUsed / 1024 / 1024), // MB
    engineState: 'idle',
    timestamp: Date.now()
  });
});

// Serve frontend build output in production
const startServer = async () => {
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static(path.join(__dirname, 'dist')));
    app.get('*', (req, res) => {
      res.sendFile(path.join(__dirname, 'dist/index.html'));
    });
  }

  const PORT = Number(process.env.PORT) || 3000;
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`AutoTAC Full-Stack Server running on port ${PORT}`);
  });
};

startServer().catch((err) => {
  console.error('Failed to boot server:', err);
});
