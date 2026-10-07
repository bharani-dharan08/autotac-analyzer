/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

export interface NetworkPacket {
  index: number;
  timestamp: number; // milliseconds
  length: number;
  protocol: 'TCP' | 'UDP' | 'ARP' | 'ICMP' | 'IPv6' | 'DNS' | 'HTTP' | 'FTP' | 'RADIUS' | 'VXLAN' | 'GENEVE' | 'BGP' | 'OSPF' | 'SIP' | 'RTP' | 'Unknown';
  srcIp: string;
  dstIp: string;
  srcPort?: number;
  dstPort?: number;
  ttl?: number;
  ipId?: number;
  tcpSeq?: number;
  tcpAck?: number;
  tcpFlags?: {
    syn: boolean;
    ack: boolean;
    fin: boolean;
    rst: boolean;
    psh: boolean;
  };
  tcpPayloadLength?: number;
  tcpWindowSize?: number;
  info: string;
  isRetransmission?: boolean;
  isDuplicateAck?: boolean;
  rtt?: number; // round-trip time in milliseconds
  dnsQuery?: {
    domain: string;
    type: string;
    isResponse: boolean;
    rcode?: number;
    rcodeName?: string;
    dnsTtl?: number;
  };
  plaintextCredentials?: {
    service: 'HTTP' | 'FTP';
    type: string;
    value: string;
  };
  tlsSni?: string;
  tlsAlertCode?: number;
  tcpOptions?: {
    mss?: number;
    windowScale?: number;
    sackPermitted?: boolean;
  };
  radiusData?: {
    code: number;
    codeName: string;
    identifier: number;
    userName: string;
    replyMessage?: string;
    eapMessage?: string;
  };
  overlayData?: {
    tunnelType: 'VXLAN' | 'GENEVE';
    outerSrcIp: string;
    outerDstIp: string;
    innerSrcIp: string;
    innerDstIp: string;
    innerSrcPort?: number;
    innerDstPort?: number;
    innerProtocol: string;
    isUnencrypted: boolean;
  };
  bgpData?: {
    type: number;
    typeName: string;
    errorCode?: number;
    errorSubcode?: number;
  };
  ospfData?: {
    version: number;
    type: number;
    typeName: string;
    routerId: string;
    ospfMtu?: number;
  };
  sipData?: {
    method?: string;
    statusCode?: number;
    statusText?: string;
    callId: string;
    from: string;
    to: string;
    cseq?: string;
    isResponse: boolean;
  };
  rtpData?: {
    version: number;
    payloadType: number;
    payloadName: string;
    sequenceNumber: number;
    timestamp: number;
    ssrc: number;
  };
}

export interface NetworkFlow {
  srcIp: string;
  dstIp: string;
  totalPackets: number;
  totalBytes: number;
  tcpPackets: number;
  retransmissions: number;
  retransmissionRate: number;
}

export interface CaptureProfilerData {
  averageFrameSize: number;
  protocolBreakdown: Array<{
    protocol: string;
    count: number;
    bytes: number;
    percentage: number;
  }>;
  commonTcpWindowSizes: Array<{
    windowSize: number;
    count: number;
    percentage: number;
  }>;
  mtuAnalysis: {
    maxFrameSize: number;
    possibleMtuIssue: boolean;
    description: string;
  };
}

export interface PcapAnalysisResult {
  totalPackets: number;
  totalBytes: number;
  captureProfiler: CaptureProfilerData;
  protocolCounts: {
    TCP: number;
    UDP: number;
    ARP: number;
    IPv6: number;
    ICMP: number;
    DNS: number;
    HTTP: number;
    FTP: number;
    VXLAN: number;
    GENEVE: number;
    SIP: number;
    RTP: number;
    Other: number;
  };
  totalTcpPackets: number;
  retransmissionCount: number;
  duplicateAckCount: number;
  globalRetransmissionRate: number;
  dnsFailureCount: number;
  plaintextCredentialsCount: number;
  connections: NetworkFlow[];
  dnsAnomalies: NetworkPacket[];
  plaintextCredentials: NetworkPacket[];
  ttlAnomalies: TtlAnomaly[];
  packets: NetworkPacket[];
  averageRtt?: number;
  maxRtt?: number;
  rttPacketsCount?: number;
  averageHandshakeRtt?: number;
  handshakeRttCount?: number;
  averageTtfb?: number;
  ttfbPacketsCount?: number;
  rstFingerprints?: RstFingerprint[];
  tlsAlerts?: TlsAlert[];
  asymmetricRouteAnomalies?: AsymmetricRouteAnomaly[];
  fingerprintedDevices?: FingerprintedDevice[];
  radiusRejects?: RadiusReject[];
  bgpNotifications?: BgpNotification[];
  ospfMismatches?: OspfMismatch[];
  voipAnalysis?: VoipQualityAnalysis;
}

export interface SipCall {
  callId: string;
  caller: string;
  callee: string;
  status: string;
  statusCode?: number;
  method?: string;
  isFailed: boolean;
  failureReason?: string;
  startTime: number;
  endTime?: number;
  durationMs?: number;
  srcIp: string;
  dstIp: string;
  messagesCount: number;
}

export interface RtpStream {
  ssrc: number;
  ssrcHex: string;
  srcIp: string;
  dstIp: string;
  srcPort: number;
  dstPort: number;
  payloadType: number;
  payloadName: string;
  packetsReceived: number;
  packetsExpected: number;
  packetsLost: number;
  packetLossPercent: number;
  jitterMs: number;
  qualityVerdict: 'Nominal (< 1% Loss)' | 'Mild Jitter (1-3% Loss)' | 'Severe Jitter & Robotic Audio (3-10% Loss)' | 'Critical Audio Drop / Unintelligible (> 10% Loss)';
}

export interface VoipQualityAnalysis {
  calls: SipCall[];
  rtpStreams: RtpStream[];
  totalCalls: number;
  failedCallsCount: number;
  maxRtpPacketLossPercent: number;
  averageJitterMs: number;
  hasSevereDegradation: boolean;
}

export interface BgpNotification {
  timestamp: number;
  srcIp: string;
  dstIp: string;
  srcPort: number;
  dstPort: number;
  errorCode: number;
  errorName: string;
  subcode: number;
  subcodeName: string;
  detail: string;
}

export interface OspfMismatch {
  timestamp: number;
  srcIp: string;
  dstIp: string;
  router1Mtu: number;
  router2Mtu: number;
  detail: string;
  verdict: 'OSPF MTU Mismatch Detected - Adjacency Stuck in EXSTART/EXCHANGE';
}

export interface RadiusReject {
  timestamp: number;
  userName: string;
  nasIp: string;
  nasPort?: number;
  respondingIamIp: string;
  replyMessage?: string;
  eapMessage?: string;
}

export interface FingerprintedDevice {
  ip: string;
  inferredOs: 'Windows' | 'Linux/Android' | 'Rogue Embedded IoT System (RTOS)' | 'Unknown/Generic';
  ttl: number;
  windowSize: number;
  mss?: number;
  windowScale?: number;
  sackPermitted: boolean;
  packetCount: number;
  isRogue: boolean;
  subnetStatus: 'Protected Subnet Breach' | 'Nominal';
  destinationsReached: string[];
}

export interface AsymmetricRouteAnomaly {
  srcIp: string;
  dstIp: string;
  srcPort?: number;
  dstPort?: number;
  firstFlagObserved: 'Orphaned ACK' | 'Orphaned PSH-ACK' | 'TTL Shift' | 'ICMP Redirect';
  ipId?: number;
  ttlValue?: number;
  detail: string;
  verdict: 'Asymmetric Return Path detected. Firewall will drop this flow as invalid state.';
  timestamp: number;
}

export interface TlsAlert {
  srcIp: string;
  dstIp: string;
  srcPort?: number;
  dstPort?: number;
  sni: string;
  alertCode: number;
  alertName: string;
  explanation: string;
  timestamp: number;
  streamId: string | number;
}

export interface RstFingerprint {
  srcIp: string;
  dstIp: string;
  srcPort?: number;
  dstPort?: number;
  rstTtl: number;
  standardTtls: number[];
  ttlDeltaCheck: string;
  verdict: 'Endpoint Application Crash (Socket Abort)' | 'Terminated By: Inline Security Device / Firewall';
  timestamp: number;
}

export interface TtlAnomaly {
  ip: string;
  ttls: number[];
  type: 'Asymmetric Routing' | 'Possible IP Spoofing' | 'Routing Loop' | 'Suspect Hop Fluctuation';
  packetCount: number;
  description: string;
}


const parseIpAddress = (buf: Buffer, offset: number): string => {
  if (offset + 4 > buf.length) return '0.0.0.0';
  return `${buf[offset]}.${buf[offset + 1]}.${buf[offset + 2]}.${buf[offset + 3]}`;
};

const getDnsRcodeName = (rcode: number): string => {
  const codes: Record<number, string> = {
    0: 'NoError',
    1: 'FormErr',
    2: 'ServFail',
    3: 'NXDomain',
    4: 'NotImpl',
    5: 'Refused',
    6: 'YXDomain',
    7: 'YXRRSet',
    8: 'NXRRSet',
    9: 'NotAuth',
    10: 'NotZone'
  };
  return codes[rcode] || `RCODE-${rcode}`;
};

const getBgpErrorDetails = (code: number, subcode: number): { errorName: string; subcodeName: string; detail: string } => {
  let errorName = 'Unknown BGP Error';
  let subcodeName = 'Unspecified';
  let detail = 'An unrecognized BGP Error occurred on the peering session.';

  if (code === 1) {
    errorName = 'Message Header Error';
    if (subcode === 1) subcodeName = 'Connection Not Synchronized';
    else if (subcode === 2) subcodeName = 'Bad Message Length';
    else if (subcode === 3) subcodeName = 'Bad Message Type';
    detail = 'Peers disagreed on base TCP framing or BGP packet header structure.';
  } else if (code === 2) {
    errorName = 'OPEN Message Error';
    if (subcode === 1) subcodeName = 'Unsupported Version Number';
    else if (subcode === 2) subcodeName = 'Bad Peer AS';
    else if (subcode === 3) subcodeName = 'Bad BGP Identifier';
    else if (subcode === 4) subcodeName = 'Unsupported Optional Parameter';
    else if (subcode === 6) subcodeName = 'Unacceptable Hold Time';
    detail = 'Configuration mismatch during peering negotiation parameters exchange.';
  } else if (code === 3) {
    errorName = 'UPDATE Message Error';
    if (subcode === 1) subcodeName = 'Malformed Attribute List';
    else if (subcode === 2) subcodeName = 'Unrecognized Well-known Attribute';
    else if (subcode === 3) subcodeName = 'Missing Well-known Attribute';
    detail = 'NLRI or path attribute errors during active route updates routing table calculations.';
  } else if (code === 4) {
    errorName = 'Hold Timer Expired';
    detail = 'The peer failed to receive BGP KEEPALIVEs or UPDATEs within the negotiated Hold Time interval. Session dropped due to keepalive packet loss.';
  } else if (code === 5) {
    errorName = 'Finite State Machine Error';
    detail = 'Finite State Machine (FSM) synchronization failure. Unexpected message received in active peering state.';
  } else if (code === 6) {
    errorName = 'Cease';
    if (subcode === 1) subcodeName = 'Maximum Number of Prefixes Reached';
    else if (subcode === 2) subcodeName = 'Administrative Shutdown';
    else if (subcode === 3) subcodeName = 'Peer De-configured';
    else if (subcode === 4) subcodeName = 'Administrative Reset';
    else if (subcode === 5) subcodeName = 'Connection Rejected';
    detail = 'Peering session actively terminated by administrator or limit exhaustion.';
  }

  return { errorName, subcodeName, detail };
};

const getRtpPayloadName = (pt: number): string => {
  switch (pt) {
    case 0: return 'G.711u (PCMU)';
    case 3: return 'GSM';
    case 4: return 'G.723';
    case 8: return 'G.711a (PCMA)';
    case 9: return 'G.722';
    case 18: return 'G.729';
    case 111: return 'Opus';
    default:
      if (pt >= 96 && pt <= 127) return `Dynamic Audio (${pt})`;
      return `PT-${pt}`;
  }
};

const cleanSipParty = (raw: string): string => {
  if (!raw) return 'Unknown';
  const match = raw.match(/"?([^"<]+)"?\s*<sip:([^>]+)>/i) || raw.match(/<sip:([^>]+)>/i) || raw.match(/sip:([^;> ]+)/i);
  if (match) {
    if (match.length >= 3 && match[1] && match[2]) {
      return `${match[1].trim()} <${match[2].trim()}>`;
    }
    return match[1].trim();
  }
  return raw.split(';')[0].trim();
};

const parseSipPayload = (text: string): NetworkPacket['sipData'] | null => {
  if (!text || text.length < 8) return null;
  const lines = text.split(/\r?\n/);
  if (lines.length === 0) return null;
  const firstLine = lines[0].trim();

  let isResponse = false;
  let statusCode: number | undefined = undefined;
  let statusText: string | undefined = undefined;
  let method: string | undefined = undefined;

  if (firstLine.startsWith('SIP/2.0 ')) {
    isResponse = true;
    const parts = firstLine.split(' ');
    statusCode = parseInt(parts[1], 10);
    statusText = parts.slice(2).join(' ') || (parts[1] || 'Status');
  } else {
    const parts = firstLine.split(' ');
    if (parts.length >= 2 && (parts[2]?.startsWith('SIP/2.0') || parts[1]?.startsWith('sip:') || parts[0]?.match(/^[A-Z]+$/))) {
      method = parts[0].toUpperCase();
    }
  }

  if (!isResponse && !method) {
    return null;
  }

  let callId = '';
  let from = '';
  let to = '';
  let cseq = '';

  for (let i = 1; i < lines.length; i++) {
    const line = lines[i];
    if (!line) continue;
    const colonIdx = line.indexOf(':');
    if (colonIdx === -1) continue;

    const headerName = line.slice(0, colonIdx).trim().toLowerCase();
    const headerVal = line.slice(colonIdx + 1).trim();

    if (headerName === 'call-id' || headerName === 'i') {
      callId = headerVal;
    } else if (headerName === 'from' || headerName === 'f') {
      from = cleanSipParty(headerVal);
    } else if (headerName === 'to' || headerName === 't') {
      to = cleanSipParty(headerVal);
    } else if (headerName === 'cseq') {
      cseq = headerVal;
    }
  }

  return {
    isResponse,
    method,
    statusCode,
    statusText,
    callId: callId || 'Unknown-Call-ID',
    from: from || 'Anonymous',
    to: to || 'Unknown-Callee',
    cseq
  };
};

export const parsePcap = (buffer: Buffer): PcapAnalysisResult => {
  const packets: NetworkPacket[] = [];
  let totalBytes = buffer.length;

  if (buffer.length < 24) {
    return createEmptyResult();
  }

  // Detect format (PCAP vs PCAPNG)
  const magic = buffer.readUInt32LE(0);
  let parsedPackets: NetworkPacket[] = [];

  if (magic === 0xa1b2c3d4 || magic === 0xd4c3b2a1 || magic === 0xa1b23c4d || magic === 0x4d3cb2a1) {
    parsedPackets = parseClassicPcap(buffer);
  } else if (magic === 0x0a0d0d0a) {
    parsedPackets = parsePcapng(buffer);
  } else {
    // Attempt parsing as classic PCAP first, fall back to PCAPNG
    try {
      parsedPackets = parseClassicPcap(buffer);
    } catch {
      try {
        parsedPackets = parsePcapng(buffer);
      } catch {
        parsedPackets = [];
      }
    }
  }

  return analyzePackets(parsedPackets);
};

const parseClassicPcap = (buffer: Buffer): NetworkPacket[] => {
  const packets: NetworkPacket[] = [];
  const magic = buffer.readUInt32LE(0);
  let isBigEndian = false;
  let isNano = false;

  if (magic === 0xa1b2c3d4) {
    isBigEndian = false;
  } else if (magic === 0xd4c3b2a1) {
    isBigEndian = true;
  } else if (magic === 0xa1b23c4d) {
    isNano = true;
    isBigEndian = false;
  } else if (magic === 0x4d3cb2a1) {
    isNano = true;
    isBigEndian = true;
  }

  const readU32 = (offset: number) => isBigEndian ? buffer.readUInt32BE(offset) : buffer.readUInt32LE(offset);
  const linkType = readU32(20);

  let offset = 24;
  let packetIdx = 0;

  while (offset + 16 <= buffer.length) {
    const tsSec = readU32(offset);
    const tsUsec = readU32(offset + 4);
    const inclLen = readU32(offset + 8);
    const origLen = readU32(offset + 12);

    offset += 16;
    if (inclLen <= 0 || inclLen > 65535) {
      // Safety limit for invalid files
      break;
    }
    if (offset + inclLen > buffer.length) break;

    const packetData = buffer.subarray(offset, offset + inclLen);
    offset += inclLen;

    const tsMs = tsSec * 1000 + (isNano ? tsUsec / 1000000 : tsUsec / 1000);

    const parsed = parsePacketBytes(packetData, packetIdx++, tsMs, linkType);
    if (parsed) {
      packets.push(parsed);
    }
  }

  return packets;
};

const parsePcapng = (buffer: Buffer): NetworkPacket[] => {
  const packets: NetworkPacket[] = [];
  let offset = 0;
  let packetIdx = 0;

  while (offset + 8 <= buffer.length) {
    const blockType = buffer.readUInt32LE(offset);
    const blockLength = buffer.readUInt32LE(offset + 4);

    if (blockLength < 12 || offset + blockLength > buffer.length) {
      break;
    }

    const blockData = buffer.subarray(offset + 8, offset + blockLength - 4);

    if (blockType === 0x00000006) {
      // Enhanced Packet Block (EPB)
      if (blockData.length >= 20) {
        const tsHigh = blockData.readUInt32LE(4);
        const tsLow = blockData.readUInt32LE(8);
        const inclLen = blockData.readUInt32LE(12);

        if (inclLen > 0 && inclLen < 65536 && 20 + inclLen <= blockData.length) {
          const tsRaw = BigInt(tsHigh) * BigInt(4294967296) + BigInt(tsLow);
          const tsMs = Number(tsRaw) / 1000; // microsecond resolution default

          const packetData = blockData.subarray(20, 20 + inclLen);
          const parsed = parsePacketBytes(packetData, packetIdx++, tsMs, 1); // assume Ethernet (1)
          if (parsed) {
            packets.push(parsed);
          }
        }
      }
    } else if (blockType === 0x00000002) {
      // Simple Packet Block (SPB)
      if (blockData.length >= 4) {
        const inclLen = blockData.readUInt32LE(0);
        if (inclLen > 0 && inclLen < 65536 && 4 + inclLen <= blockData.length) {
          const packetData = blockData.subarray(4, 4 + inclLen);
          const parsed = parsePacketBytes(packetData, packetIdx++, Date.now(), 1);
          if (parsed) {
            packets.push(parsed);
          }
        }
      }
    }

    offset += blockLength;
  }

  return packets;
};

const parsePacketBytes = (
  packet: Buffer,
  index: number,
  timestamp: number,
  linkType: number
): NetworkPacket | null => {
  // We only support Ethernet (1) link type for full extraction
  if (linkType !== 1 || packet.length < 14) {
    return {
      index,
      timestamp,
      length: packet.length,
      protocol: 'Unknown',
      srcIp: 'Unknown',
      dstIp: 'Unknown',
      info: 'Unknown Link-Layer Data'
    };
  }

  const etherType = packet.readUInt16BE(12);

  // ARP (0x0806)
  if (etherType === 0x0806) {
    if (packet.length >= 28) {
      const senderIp = parseIpAddress(packet, 28);
      const targetIp = parseIpAddress(packet, 38);
      const op = packet.readUInt16BE(20);
      const isRequest = op === 1;
      return {
        index,
        timestamp,
        length: packet.length,
        protocol: 'ARP',
        srcIp: senderIp,
        dstIp: targetIp,
        info: isRequest ? `Who has ${targetIp}? Tell ${senderIp}` : `${senderIp} is at ${packet.subarray(22, 28).toString('hex').match(/.{1,2}/g)?.join(':') || 'MAC'}`
      };
    }
    return {
      index,
      timestamp,
      length: packet.length,
      protocol: 'ARP',
      srcIp: 'ARP Sender',
      dstIp: 'ARP Target',
      info: 'ARP Packet'
    };
  }

  // IPv6 (0x86dd)
  if (etherType === 0x86dd) {
    return {
      index,
      timestamp,
      length: packet.length,
      protocol: 'IPv6',
      srcIp: 'IPv6 Host',
      dstIp: 'IPv6 Host',
      info: 'IPv6 Packet (Extraction Limited)'
    };
  }

  // IPv4 (0x0800)
  if (etherType === 0x0800 && packet.length >= 34) {
    const ipHeaderOffset = 14;
    const versionIhl = packet[ipHeaderOffset];
    const ihl = (versionIhl & 0x0f) * 4;
    const protocol = packet[ipHeaderOffset + 9];
    const ttl = packet[ipHeaderOffset + 8];
    const totalLen = packet.readUInt16BE(ipHeaderOffset + 2);
    const ipId = packet.readUInt16BE(ipHeaderOffset + 4);

    const srcIp = parseIpAddress(packet, ipHeaderOffset + 12);
    const dstIp = parseIpAddress(packet, ipHeaderOffset + 16);

    // Check bounds
    if (ipHeaderOffset + ihl > packet.length) {
      return {
        index,
        timestamp,
        length: packet.length,
        protocol: 'Unknown',
        srcIp,
        dstIp,
        info: 'Malformed IPv4 header'
      };
    }

    // TCP (6)
    if (protocol === 6) {
      const tcpOffset = ipHeaderOffset + ihl;
      if (tcpOffset + 20 <= packet.length) {
        const srcPort = packet.readUInt16BE(tcpOffset);
        const dstPort = packet.readUInt16BE(tcpOffset + 2);
        const tcpSeq = packet.readUInt32BE(tcpOffset + 4);
        const tcpAck = packet.readUInt32BE(tcpOffset + 8);
        const dataOffset = ((packet[tcpOffset + 12] & 0xf0) >> 4) * 4;
        const flagsByte = packet[tcpOffset + 13];

        const tcpFlags = {
          syn: (flagsByte & 0x02) !== 0,
          ack: (flagsByte & 0x10) !== 0,
          fin: (flagsByte & 0x01) !== 0,
          rst: (flagsByte & 0x04) !== 0,
          psh: (flagsByte & 0x08) !== 0
        };

        const tcpPayloadOffset = tcpOffset + dataOffset;
        const tcpPayloadLength = Math.max(0, totalLen - ihl - dataOffset);
        const tcpWindowSize = packet.readUInt16BE(tcpOffset + 14);

        let mssValue: number | undefined = undefined;
        let windowScaleValue: number | undefined = undefined;
        let sackPermittedValue = false;

        if (dataOffset > 20) {
          let optOffset = tcpOffset + 20;
          const optEnd = tcpOffset + dataOffset;
          while (optOffset < optEnd) {
            const optType = packet[optOffset];
            if (optType === 0) {
              break;
            }
            if (optType === 1) {
              optOffset++;
              continue;
            }
            if (optOffset + 1 >= optEnd) {
              break;
            }
            const optLen = packet[optOffset + 1];
            if (optLen <= 1 || optOffset + optLen > optEnd) {
              break;
            }
            if (optType === 2 && optLen === 4) {
              mssValue = packet.readUInt16BE(optOffset + 2);
            } else if (optType === 3 && optLen === 3) {
              windowScaleValue = packet[optOffset + 2];
            } else if (optType === 4 && optLen === 2) {
              sackPermittedValue = true;
            }
            optOffset += optLen;
          }
        }

        const tcpOptions = {
          mss: mssValue,
          windowScale: windowScaleValue,
          sackPermitted: sackPermittedValue
        };

        let info = `${srcPort} → ${dstPort} [`;
        const activeFlags: string[] = [];
        if (tcpFlags.syn) activeFlags.push('SYN');
        if (tcpFlags.ack) activeFlags.push('ACK');
        if (tcpFlags.fin) activeFlags.push('FIN');
        if (tcpFlags.rst) activeFlags.push('RST');
        if (tcpFlags.psh) activeFlags.push('PSH');
        info += activeFlags.join(', ');
        info += `] Seq=${tcpSeq} Ack=${tcpAck} Win=${packet.readUInt16BE(tcpOffset + 14)} Len=${tcpPayloadLength}`;

        // Extract plaintext credentials if any
        let plaintextCredentials: NetworkPacket['plaintextCredentials'] | undefined = undefined;
        let pLabel: NetworkPacket['protocol'] = 'TCP';
        let localTlsSni: string | undefined = undefined;
        let localTlsAlertCode: number | undefined = undefined;

        if (tcpPayloadLength > 0 && tcpPayloadOffset + tcpPayloadLength <= packet.length) {
          const payloadBuffer = packet.subarray(tcpPayloadOffset, tcpPayloadOffset + tcpPayloadLength);
          const payloadStr = payloadBuffer.toString('utf8');

          // Detect HTTP Port or signature
          if (dstPort === 80 || srcPort === 80 || dstPort === 8080 || srcPort === 8080 || payloadStr.includes('HTTP/')) {
            pLabel = 'HTTP';
            // HTTP Authorization Header (Basic Auth)
            const basicAuthMatch = payloadStr.match(/Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)/i);
            if (basicAuthMatch && basicAuthMatch[1]) {
              try {
                const decoded = Buffer.from(basicAuthMatch[1], 'base64').toString('utf8');
                plaintextCredentials = {
                  service: 'HTTP',
                  type: 'HTTP Basic Auth Header',
                  value: decoded
                };
              } catch {}
            }

            // HTTP POST Forms containing logins
            const formLoginMatch = payloadStr.match(/user(?:name)?=([^&]+).*pass(?:word)?=([^& \r\n]+)/i);
            if (formLoginMatch && formLoginMatch[1] && formLoginMatch[2]) {
              plaintextCredentials = {
                service: 'HTTP',
                type: 'HTTP POST Body Credentials',
                value: `User: ${decodeURIComponent(formLoginMatch[1])} | Pass: ${decodeURIComponent(formLoginMatch[2])}`
              };
            }
          }

          // Detect FTP Port 21
          if (dstPort === 21 || srcPort === 21) {
            pLabel = 'FTP';
            const ftpUserMatch = payloadStr.match(/^USER\s+(\S+)/i);
            const ftpPassMatch = payloadStr.match(/^PASS\s+(\S+)/i);
            if (ftpUserMatch) {
              plaintextCredentials = {
                service: 'FTP',
                type: 'FTP USER Command',
                value: `Username: ${ftpUserMatch[1]}`
              };
            } else if (ftpPassMatch) {
              plaintextCredentials = {
                service: 'FTP',
                type: 'FTP PASS Command',
                value: `Password: ${ftpPassMatch[1]}`
              };
            }
          }

          // Detect TLS (HTTPS Port 443 or TLS record Content-Types)

          if (dstPort === 443 || srcPort === 443 || payloadBuffer[0] === 0x16 || payloadBuffer[0] === 0x15) {
            const contentType = payloadBuffer[0];
            const majorVersion = payloadBuffer[1];

            if (majorVersion === 3 && contentType >= 20 && contentType <= 23) {
              // TLS Alert Packet (Content Type 21)
              if (contentType === 0x15 && payloadBuffer.length >= 7) {
                localTlsAlertCode = payloadBuffer[6];
              }

              // TLS Client Hello (Content Type 22, Handshake Type 1 Client Hello)
              if (contentType === 0x16 && payloadBuffer.length >= 43 && payloadBuffer[5] === 0x01) {
                try {
                  const payloadStr = payloadBuffer.toString('ascii');
                  const matches = payloadStr.match(/[a-z0-9-]+\.[a-z0-9.-]{2,63}/gi);
                  if (matches && matches.length > 0) {
                    const validDomain = matches.find(m => !m.includes('http') && !m.includes('Mozilla') && m.length > 4);
                    if (validDomain) {
                      localTlsSni = validDomain.toLowerCase();
                    }
                  }
                } catch {}
              }
            }
          }
        }

        let localBgpData: NetworkPacket['bgpData'] | undefined = undefined;

        if (dstPort === 179 || srcPort === 179) {
          pLabel = 'BGP';
          if (tcpPayloadLength >= 19 && tcpPayloadOffset + tcpPayloadLength <= packet.length) {
            const bgpType = packet[tcpPayloadOffset + 18];
            let typeName = 'Unknown';
            if (bgpType === 1) typeName = 'OPEN';
            else if (bgpType === 2) typeName = 'UPDATE';
            else if (bgpType === 3) typeName = 'NOTIFICATION';
            else if (bgpType === 4) typeName = 'KEEPALIVE';
            else if (bgpType === 5) typeName = 'ROUTE-REFRESH';

            let errorCode: number | undefined = undefined;
            let errorSubcode: number | undefined = undefined;

            if (bgpType === 3 && tcpPayloadLength >= 21) {
              errorCode = packet[tcpPayloadOffset + 19];
              errorSubcode = packet[tcpPayloadOffset + 20];
              info = `BGP NOTIFICATION: Error Code ${errorCode}, Subcode ${errorSubcode}`;
            } else {
              info = `BGP ${typeName} Message`;
            }

            localBgpData = {
              type: bgpType,
              typeName,
              errorCode,
              errorSubcode
            };
          } else {
            info = `BGP Keepalive or TCP Control Message`;
          }
        }

        let localSipData: NetworkPacket['sipData'] | undefined = undefined;
        if (srcPort === 5060 || dstPort === 5060) {
          pLabel = 'SIP';
          if (tcpPayloadOffset < packet.length) {
            const tcpText = packet.subarray(tcpPayloadOffset, Math.min(packet.length, tcpPayloadOffset + 1400)).toString('ascii');
            const sip = parseSipPayload(tcpText);
            if (sip) {
              localSipData = sip;
              if (sip.isResponse) {
                info = `SIP/2.0 ${sip.statusCode} ${sip.statusText} [Call-ID: ${sip.callId.slice(0, 20)}]`;
              } else {
                info = `SIP ${sip.method}: ${sip.to} [From: ${sip.from}]`;
              }
            } else {
              info = `SIP Signaling (TCP 5060)`;
            }
          }
        }

          // Return values
          const p: NetworkPacket = {
            index,
            timestamp,
            length: packet.length,
            protocol: pLabel,
            srcIp,
            dstIp,
            srcPort,
            dstPort,
            ttl,
            ipId,
            tcpSeq,
            tcpAck,
            tcpFlags,
            tcpPayloadLength,
            tcpWindowSize,
            plaintextCredentials,
            tlsSni: localTlsSni,
            tlsAlertCode: localTlsAlertCode,
            tcpOptions,
            bgpData: localBgpData,
            sipData: localSipData,
            info
          };
          return p;
      }
    }

    // UDP (17)
    if (protocol === 17) {
      const udpOffset = ipHeaderOffset + ihl;
      if (udpOffset + 8 <= packet.length) {
        const srcPort = packet.readUInt16BE(udpOffset);
        const dstPort = packet.readUInt16BE(udpOffset + 2);
        const udpLen = packet.readUInt16BE(udpOffset + 4);

        let info = `UDP: ${srcPort} → ${dstPort} Len=${udpLen - 8}`;
        let dnsQuery: NetworkPacket['dnsQuery'] | undefined = undefined;
        let isDns = dstPort === 53 || srcPort === 53;

        let radiusDataValue: NetworkPacket['radiusData'] | undefined = undefined;
        const isRadius = dstPort === 1812 || srcPort === 1812 || dstPort === 1813 || srcPort === 1813;

        if (isRadius) {
          const radiusOffset = udpOffset + 8;
          if (radiusOffset + 20 <= packet.length) {
            const radCode = packet[radiusOffset];
            const radId = packet[radiusOffset + 1];
            const radLen = packet.readUInt16BE(radiusOffset + 2);

            let codeName = 'Unknown';
            if (radCode === 1) codeName = 'Access-Request';
            else if (radCode === 2) codeName = 'Access-Accept';
            else if (radCode === 3) codeName = 'Access-Reject';
            else if (radCode === 4) codeName = 'Accounting-Request';
            else if (radCode === 5) codeName = 'Accounting-Response';

            let userName = '';
            let replyMessage = '';
            let eapMessage = '';

            let attrOffset = radiusOffset + 20;
            const attrEnd = Math.min(packet.length, radiusOffset + radLen);

            while (attrOffset + 2 <= attrEnd) {
              const attrType = packet[attrOffset];
              const attrLen = packet[attrOffset + 1];
              if (attrLen < 2 || attrOffset + attrLen > attrEnd) {
                break;
              }

              const attrValOffset = attrOffset + 2;
              const attrValLen = attrLen - 2;

              if (attrType === 1) {
                userName = packet.subarray(attrValOffset, attrValOffset + attrValLen).toString('ascii').replace(/[^\x20-\x7E]/g, '');
              } else if (attrType === 18) {
                replyMessage = packet.subarray(attrValOffset, attrValOffset + attrValLen).toString('ascii').replace(/[^\x20-\x7E]/g, '');
              } else if (attrType === 79) {
                eapMessage = "EAP payload present";
              }

              attrOffset += attrLen;
            }

            radiusDataValue = {
              code: radCode,
              codeName,
              identifier: radId,
              userName,
              replyMessage,
              eapMessage
            };

            info = `RADIUS ${codeName}: ID=${radId} User=${userName || 'None'}`;
            if (replyMessage) {
              info += ` Msg="${replyMessage}"`;
            }
          }
        }

        if (isDns) {
          const dnsOffset = udpOffset + 8;
          if (dnsOffset + 12 <= packet.length) {
            const dnsId = packet.readUInt16BE(dnsOffset);
            const dnsFlags = packet.readUInt16BE(dnsOffset + 2);
            const qCount = packet.readUInt16BE(dnsOffset + 4);
            const aCount = packet.readUInt16BE(dnsOffset + 6);

            const isResponse = (dnsFlags & 0x8000) !== 0;
            const rcode = dnsFlags & 0x000f;
            const rcodeName = getDnsRcodeName(rcode);

            // Simple name parser for DNS Question
            let p = dnsOffset + 12;
            let domainParts: string[] = [];
            while (p < packet.length) {
              const len = packet[p];
              if (len === 0) {
                p++;
                break;
              }
              if ((len & 0xc0) === 0xc0) {
                p += 2; // Pointer
                break;
              }
              p++;
              if (p + len <= packet.length) {
                const part = packet.subarray(p, p + len).toString('ascii');
                // Filter printable characters to avoid garbage
                const cleanPart = part.replace(/[^ -~]/g, '');
                if (cleanPart) domainParts.push(cleanPart);
                p += len;
              } else {
                break;
              }
            }
            const domain = domainParts.join('.') || 'Unknown';

            let dnsTtl: number | undefined = undefined;
            if (isResponse && aCount > 0) {
              const ansPos = p + 4; // skip QType (2B) and QClass (2B)
              if (ansPos + 10 <= packet.length) {
                // Answer record starts at ansPos.
                // Format: Name (2B pointer), Type (2B), Class (2B), TTL (4B) -> TTL is at ansPos + 6
                dnsTtl = packet.readUInt32BE(ansPos + 6);
              }
            }

            dnsQuery = {
              domain,
              type: qCount > 0 ? 'A' : 'Unknown',
              isResponse,
              rcode,
              rcodeName,
              dnsTtl
            };

            let ttlInfo = '';
            if (dnsTtl !== undefined) {
              ttlInfo = ` TTL=${dnsTtl}s`;
            }
            info = `DNS ${isResponse ? 'Response' : 'Query'} [ID=${dnsId}]: ${domain} (${rcodeName})${ttlInfo}`;
          }
        }

        let overlayDataValue: NetworkPacket['overlayData'] | undefined = undefined;
        const isVxlan = dstPort === 4789 || srcPort === 4789;
        const isGeneve = dstPort === 6081 || srcPort === 6081;

        if (isVxlan) {
          const vxlanOffset = udpOffset + 8;
          if (vxlanOffset + 8 <= packet.length) {
            let innerIpOffset = vxlanOffset + 8;
            if (innerIpOffset + 14 <= packet.length) {
              const etherType = packet.readUInt16BE(innerIpOffset + 12);
              if (etherType === 0x0800) {
                innerIpOffset += 14;
              }
            }

            if (innerIpOffset + 20 <= packet.length) {
              const innerVersionIhl = packet[innerIpOffset];
              const innerVersion = innerVersionIhl >> 4;
              const innerIhl = (innerVersionIhl & 0x0f) * 4;
              if (innerVersion === 4 && innerIpOffset + innerIhl <= packet.length) {
                const innerSrcIp = `${packet[innerIpOffset + 12]}.${packet[innerIpOffset + 13]}.${packet[innerIpOffset + 14]}.${packet[innerIpOffset + 15]}`;
                const innerDstIp = `${packet[innerIpOffset + 16]}.${packet[innerIpOffset + 17]}.${packet[innerIpOffset + 18]}.${packet[innerIpOffset + 19]}`;
                const innerProto = packet[innerIpOffset + 9];

                let innerSrcPort: number | undefined = undefined;
                let innerDstPort: number | undefined = undefined;
                let innerProtocol = 'Unknown';

                if (innerProto === 6) {
                  innerProtocol = 'TCP';
                  const tcpOffset = innerIpOffset + innerIhl;
                  if (tcpOffset + 4 <= packet.length) {
                    innerSrcPort = packet.readUInt16BE(tcpOffset);
                    innerDstPort = packet.readUInt16BE(tcpOffset + 2);
                    if (innerDstPort === 80 || innerSrcPort === 80) {
                      innerProtocol = 'HTTP';
                    } else if (innerDstPort === 443 || innerSrcPort === 443) {
                      innerProtocol = 'TLS';
                    }
                  }
                } else if (innerProto === 17) {
                  innerProtocol = 'UDP';
                  const udpOffsetInner = innerIpOffset + innerIhl;
                  if (udpOffsetInner + 4 <= packet.length) {
                    innerSrcPort = packet.readUInt16BE(udpOffsetInner);
                    innerDstPort = packet.readUInt16BE(udpOffsetInner + 2);
                  }
                } else if (innerProto === 1) {
                  innerProtocol = 'ICMP';
                }

                const isUnencrypted = innerProtocol === 'HTTP' || innerProtocol === 'Unknown' || (innerProtocol === 'TCP' && (innerDstPort === 80 || innerSrcPort === 80));

                overlayDataValue = {
                  tunnelType: 'VXLAN',
                  outerSrcIp: srcIp,
                  outerDstIp: dstIp,
                  innerSrcIp,
                  innerDstIp,
                  innerSrcPort,
                  innerDstPort,
                  innerProtocol,
                  isUnencrypted
                };

                info = `VXLAN Tunnel: [${srcIp} → ${dstIp}] Decapsulated Inner: [${innerSrcIp}${innerSrcPort ? `:${innerSrcPort}` : ''} → ${innerDstIp}${innerDstPort ? `:${innerDstPort}` : ''}] (${innerProtocol})`;
              }
            }
          }
        } else if (isGeneve) {
          const geneveOffset = udpOffset + 8;
          if (geneveOffset + 8 <= packet.length) {
            const versionAndOptLen = packet[geneveOffset];
            const optLen = (versionAndOptLen & 0x3f) * 4;
            const protocolType = packet.readUInt16BE(geneveOffset + 2);

            let innerIpOffset = geneveOffset + 8 + optLen;

            if (protocolType === 0x6558 && innerIpOffset + 14 <= packet.length) {
              const etherType = packet.readUInt16BE(innerIpOffset + 12);
              if (etherType === 0x0800) {
                innerIpOffset += 14;
              }
            }

            if (innerIpOffset + 20 <= packet.length) {
              const innerVersionIhl = packet[innerIpOffset];
              const innerVersion = innerVersionIhl >> 4;
              const innerIhl = (innerVersionIhl & 0x0f) * 4;
              if (innerVersion === 4 && innerIpOffset + innerIhl <= packet.length) {
                const innerSrcIp = `${packet[innerIpOffset + 12]}.${packet[innerIpOffset + 13]}.${packet[innerIpOffset + 14]}.${packet[innerIpOffset + 15]}`;
                const innerDstIp = `${packet[innerIpOffset + 16]}.${packet[innerIpOffset + 17]}.${packet[innerIpOffset + 18]}.${packet[innerIpOffset + 19]}`;
                const innerProto = packet[innerIpOffset + 9];

                let innerSrcPort: number | undefined = undefined;
                let innerDstPort: number | undefined = undefined;
                let innerProtocol = 'Unknown';

                if (innerProto === 6) {
                  innerProtocol = 'TCP';
                  const tcpOffset = innerIpOffset + innerIhl;
                  if (tcpOffset + 4 <= packet.length) {
                    innerSrcPort = packet.readUInt16BE(tcpOffset);
                    innerDstPort = packet.readUInt16BE(tcpOffset + 2);
                    if (innerDstPort === 80 || innerSrcPort === 80) {
                      innerProtocol = 'HTTP';
                    } else if (innerDstPort === 443 || innerSrcPort === 443) {
                      innerProtocol = 'TLS';
                    }
                  }
                } else if (innerProto === 17) {
                  innerProtocol = 'UDP';
                  const udpOffsetInner = innerIpOffset + innerIhl;
                  if (udpOffsetInner + 4 <= packet.length) {
                    innerSrcPort = packet.readUInt16BE(udpOffsetInner);
                    innerDstPort = packet.readUInt16BE(udpOffsetInner + 2);
                  }
                } else if (innerProto === 1) {
                  innerProtocol = 'ICMP';
                }

                const isUnencrypted = innerProtocol === 'HTTP' || innerProtocol === 'Unknown' || (innerProtocol === 'TCP' && (innerDstPort === 80 || innerSrcPort === 80));

                overlayDataValue = {
                  tunnelType: 'GENEVE',
                  outerSrcIp: srcIp,
                  outerDstIp: dstIp,
                  innerSrcIp,
                  innerDstIp,
                  innerSrcPort,
                  innerDstPort,
                  innerProtocol,
                  isUnencrypted
                };

                info = `GENEVE Tunnel: [${srcIp} → ${dstIp}] Decapsulated Inner: [${innerSrcIp}${innerSrcPort ? `:${innerSrcPort}` : ''} → ${innerDstIp}${innerDstPort ? `:${innerDstPort}` : ''}] (${innerProtocol})`;
              }
            }
          }
        }

        let sipDataValue: NetworkPacket['sipData'] | undefined = undefined;
        let rtpDataValue: NetworkPacket['rtpData'] | undefined = undefined;
        const isSip = dstPort === 5060 || srcPort === 5060;

        if (isSip) {
          const udpPayloadOffset = udpOffset + 8;
          if (udpPayloadOffset < packet.length) {
            const sipText = packet.subarray(udpPayloadOffset, Math.min(packet.length, udpPayloadOffset + 1400)).toString('ascii');
            const sip = parseSipPayload(sipText);
            if (sip) {
              sipDataValue = sip;
              if (sip.isResponse) {
                info = `SIP/2.0 ${sip.statusCode} ${sip.statusText} [Call-ID: ${sip.callId.slice(0, 20)}]`;
              } else {
                info = `SIP ${sip.method}: ${sip.to} [From: ${sip.from}]`;
              }
            } else {
              info = `SIP Signaling (UDP 5060)`;
            }
          }
        }

        // RTP audio detection (if not DNS, RADIUS, SIP, VXLAN, GENEVE)
        if (!isDns && !isRadius && !isSip && !overlayDataValue) {
          const udpPayloadOffset = udpOffset + 8;
          const udpPayloadLen = udpLen - 8;
          if (udpPayloadLen >= 12 && udpPayloadOffset + 12 <= packet.length) {
            const b0 = packet[udpPayloadOffset];
            const b1 = packet[udpPayloadOffset + 1];
            // Check RTP version: (b0 >> 6) === 2 (0x80)
            if ((b0 & 0xc0) === 0x80) {
              const pt = b1 & 0x7f;
              // Check payload type: audio <= 34 or dynamic (96-127)
              if (pt <= 34 || (pt >= 96 && pt <= 127)) {
                const seq = packet.readUInt16BE(udpPayloadOffset + 2);
                const ts = packet.readUInt32BE(udpPayloadOffset + 4);
                const ssrc = packet.readUInt32BE(udpPayloadOffset + 8);
                const payloadName = getRtpPayloadName(pt);

                rtpDataValue = {
                  version: 2,
                  payloadType: pt,
                  payloadName,
                  sequenceNumber: seq,
                  timestamp: ts,
                  ssrc
                };
                info = `RTP Audio: Seq=${seq}, SSRC=0x${ssrc.toString(16).toUpperCase()}, PT=${payloadName}`;
              }
            }
          }
        }

        let protoLabel: NetworkPacket['protocol'] = 'UDP';
        if (isDns) protoLabel = 'DNS';
        else if (isRadius) protoLabel = 'RADIUS';
        else if (isSip && sipDataValue) protoLabel = 'SIP';
        else if (rtpDataValue) protoLabel = 'RTP';
        else if (overlayDataValue) protoLabel = overlayDataValue.tunnelType;

        return {
          index,
          timestamp,
          length: packet.length,
          protocol: protoLabel,
          srcIp,
          dstIp,
          srcPort,
          dstPort,
          ttl,
          ipId,
          dnsQuery,
          radiusData: radiusDataValue,
          overlayData: overlayDataValue,
          sipData: sipDataValue,
          rtpData: rtpDataValue,
          info
        };
      }
    }

    // ICMP (1)
    if (protocol === 1) {
      const icmpOffset = ipHeaderOffset + ihl;
      if (icmpOffset < packet.length) {
        const type = packet[icmpOffset];
        const code = packet[icmpOffset + 1];
        let icmpTypeStr = 'Echo Request';
        if (type === 0) icmpTypeStr = 'Echo Reply';
        if (type === 3) icmpTypeStr = 'Destination Unreachable';
        if (type === 11) icmpTypeStr = 'Time Exceeded';

        return {
          index,
          timestamp,
          length: packet.length,
          protocol: 'ICMP',
          srcIp,
          dstIp,
          ttl,
          ipId,
          info: `ICMP ${icmpTypeStr} (type=${type}, code=${code})`
        };
      }
    }

    // OSPF (89)
    if (protocol === 89) {
      const ospfOffset = ipHeaderOffset + ihl;
      if (ospfOffset + 24 <= packet.length) {
        const version = packet[ospfOffset];
        const type = packet[ospfOffset + 1];
        const routerId = `${packet[ospfOffset + 4]}.${packet[ospfOffset + 5]}.${packet[ospfOffset + 6]}.${packet[ospfOffset + 7]}`;

        let typeName = 'Unknown';
        if (type === 1) typeName = 'HELLO';
        else if (type === 2) typeName = 'DBD';
        else if (type === 3) typeName = 'LSR';
        else if (type === 4) typeName = 'LSU';
        else if (type === 5) typeName = 'LSAck';

        let ospfMtu: number | undefined = undefined;
        if (type === 2 && ospfOffset + 26 <= packet.length) {
          ospfMtu = packet.readUInt16BE(ospfOffset + 24);
        }

        const info = `OSPFv${version} ${typeName}: RouterID=${routerId}${ospfMtu !== undefined ? ` MTU=${ospfMtu}` : ''}`;

        return {
          index,
          timestamp,
          length: packet.length,
          protocol: 'OSPF',
          srcIp,
          dstIp,
          ttl,
          ipId,
          ospfData: {
            version,
            type,
            typeName,
            routerId,
            ospfMtu
          },
          info
        };
      }
    }

    return {
      index,
      timestamp,
      length: packet.length,
      protocol: 'Unknown',
      srcIp,
      dstIp,
      ttl,
      ipId,
      info: `IPv4 Protocol ${protocol}`
    };
  }

  return {
    index,
    timestamp,
    length: packet.length,
    protocol: 'Unknown',
    srcIp: 'Unknown',
    dstIp: 'Unknown',
    info: `Ethernet frame (Type: 0x${etherType.toString(16)})`
  };
};

const createEmptyResult = (): PcapAnalysisResult => ({
  totalPackets: 0,
  totalBytes: 0,
  protocolCounts: { TCP: 0, UDP: 0, ARP: 0, IPv6: 0, ICMP: 0, DNS: 0, HTTP: 0, FTP: 0, VXLAN: 0, GENEVE: 0, SIP: 0, RTP: 0, Other: 0 },
  totalTcpPackets: 0,
  retransmissionCount: 0,
  duplicateAckCount: 0,
  globalRetransmissionRate: 0,
  dnsFailureCount: 0,
  plaintextCredentialsCount: 0,
  connections: [],
  dnsAnomalies: [],
  plaintextCredentials: [],
  ttlAnomalies: [],
  packets: [],
  averageRtt: 0,
  maxRtt: 0,
  rttPacketsCount: 0,
  averageHandshakeRtt: 0,
  handshakeRttCount: 0,
  averageTtfb: 0,
  ttfbPacketsCount: 0,
  rstFingerprints: [],
  tlsAlerts: [],
  asymmetricRouteAnomalies: [],
  captureProfiler: {
    averageFrameSize: 0,
    protocolBreakdown: [],
    commonTcpWindowSizes: [],
    mtuAnalysis: { maxFrameSize: 0, possibleMtuIssue: false, description: 'No capture analyzed' }
  }
});

const analyzePackets = (packets: NetworkPacket[]): PcapAnalysisResult => {
  const result = createEmptyResult();
  result.totalPackets = packets.length;

  // Track bytes per protocol for breakdown
  const protocolBytes: Record<string, number> = { TCP: 0, UDP: 0, ARP: 0, IPv6: 0, ICMP: 0, DNS: 0, HTTP: 0, FTP: 0, VXLAN: 0, GENEVE: 0, SIP: 0, RTP: 0, Other: 0 };
  const windowSizeCounts: Record<number, number> = {};

  // Track sequence numbers for TCP Retransmission detection
  // Key: flow key "srcIp:srcPort -> dstIp:dstPort"
  // Value: list of sequence numbers and lengths already seen
  const tcpSequences: Record<string, { seq: number; len: number; ts: number }[]> = {};

  // Track reverse ACKs to detect Duplicate ACKs
  // Key: flow key "srcIp:srcPort -> dstIp:dstPort"
  // Value: last ACK number seen, count, and packet info
  const tcpLastAck: Record<string, { ack: number; win: number; count: number }> = {};

  // Track flows to summarize connections
  // Key: "srcIp -> dstIp"
  const flows: Record<string, { totalBytes: number; totalPackets: number; tcpPackets: number; retransmissions: number }> = {};

  // Stateful Firewall Asymmetric Routing Trackers
  const tcpSeenFlows = new Set<string>();
  const tcpFlowTtls: Record<string, number> = {};
  const asymmetricRouteAnomalies: AsymmetricRouteAnomaly[] = [];

  // Track TTL values per IP to detect Spoofing/Asymmetric routing
  const ipTtls: Record<string, { ttls: Set<number>; packetCount: number }> = {};

  // Track outstanding segments for TCP stream RTT estimation
  const outstandingTcpSegments: Record<string, { expectedAck: number; ts: number }[]> = {};
  const rttValues: number[] = [];

  // Track client handshake SYN timestamps
  const handshakeSynTime: Record<string, number> = {};
  const handshakeRtts: number[] = [];

  // Track HTTP client request timestamps for TTFB calculation
  const httpRequestTime: Record<string, number> = {};
  const serverTtfbs: number[] = [];

  // Track standard non-RST TTL values per source IP for middlebox fingerprinting
  const ipStandardTtls: Record<string, Set<number>> = {};
  const rstFingerprints: RstFingerprint[] = [];

  // Track TLS SNI server names and Alert messages
  const tlsStreamSni: Record<string, string> = {};
  const tlsAlerts: TlsAlert[] = [];

  packets.forEach((p) => {
    // Protocol counts counting and byte tracking
    if (p.protocol === 'TCP') { result.protocolCounts.TCP++; protocolBytes.TCP += p.length; }
    else if (p.protocol === 'UDP') { result.protocolCounts.UDP++; protocolBytes.UDP += p.length; }
    else if (p.protocol === 'ARP') { result.protocolCounts.ARP++; protocolBytes.ARP += p.length; }
    else if (p.protocol === 'IPv6') { result.protocolCounts.IPv6++; protocolBytes.IPv6 += p.length; }
    else if (p.protocol === 'ICMP') { result.protocolCounts.ICMP++; protocolBytes.ICMP += p.length; }
    else if (p.protocol === 'DNS') { result.protocolCounts.DNS++; protocolBytes.DNS += p.length; }
    else if (p.protocol === 'HTTP') { result.protocolCounts.HTTP++; protocolBytes.HTTP += p.length; }
    else if (p.protocol === 'FTP') { result.protocolCounts.FTP++; protocolBytes.FTP += p.length; }
    else if (p.protocol === 'VXLAN') { result.protocolCounts.VXLAN++; protocolBytes.VXLAN += p.length; }
    else if (p.protocol === 'GENEVE') { result.protocolCounts.GENEVE++; protocolBytes.GENEVE += p.length; }
    else if (p.protocol === 'SIP') { result.protocolCounts.SIP++; protocolBytes.SIP += p.length; }
    else if (p.protocol === 'RTP') { result.protocolCounts.RTP++; protocolBytes.RTP += p.length; }
    else { result.protocolCounts.Other++; protocolBytes.Other += p.length; }

    if (p.tcpWindowSize !== undefined) {
      windowSizeCounts[p.tcpWindowSize] = (windowSizeCounts[p.tcpWindowSize] || 0) + 1;
    }

    result.totalBytes += p.length;

    const hasIp = p.srcIp !== 'Unknown' && p.dstIp !== 'Unknown';

    if (hasIp) {
      const flowKey = `${p.srcIp} -> ${p.dstIp}`;
      if (!flows[flowKey]) {
        flows[flowKey] = { totalBytes: 0, totalPackets: 0, tcpPackets: 0, retransmissions: 0 };
      }
      flows[flowKey].totalBytes += p.length;
      flows[flowKey].totalPackets++;

      const isTcpProto = p.protocol === 'TCP' || p.protocol === 'HTTP' || p.protocol === 'FTP';

      if (isTcpProto) {
        flows[flowKey].tcpPackets++;
        result.totalTcpPackets++;

        // Perform TCP Retransmission Check
        const connKey = `${p.srcIp}:${p.srcPort} -> ${p.dstIp}:${p.dstPort}`;
        const seq = p.tcpSeq ?? 0;
        const len = p.tcpPayloadLength ?? 0;
        const isSyn = p.tcpFlags?.syn ?? false;
        const isFin = p.tcpFlags?.fin ?? false;

        // --- Stateful Firewall Asymmetric Bypass Checks ---
        const isAck = p.tcpFlags?.ack ?? false;
        const isPsh = p.tcpFlags?.psh ?? false;

        if (!tcpSeenFlows.has(connKey)) {
          tcpSeenFlows.add(connKey);
          // If the first packet of a connection is ACK or PSH-ACK, but not SYN:
          if (isAck && !isSyn) {
            const label = isPsh ? 'Orphaned PSH-ACK' : 'Orphaned ACK';
            asymmetricRouteAnomalies.push({
              srcIp: p.srcIp,
              dstIp: p.dstIp,
              srcPort: p.srcPort,
              dstPort: p.dstPort,
              firstFlagObserved: label,
              ipId: p.ipId,
              ttlValue: p.ttl,
              detail: `TCP connection flow started mid-stream without handshake synchronization (First frame: ${isPsh ? 'PSH-ACK' : 'ACK'}). This indicates the SYN/SYN-ACK packets traversed an alternate network interface bypassing state checks.`,
              verdict: 'Asymmetric Return Path detected. Firewall will drop this flow as invalid state.',
              timestamp: p.timestamp
            });
          }
        }

        // Check for TTL Shifts inside the same connection flow to signal path change
        if (p.ttl !== undefined) {
          const previousTtl = tcpFlowTtls[connKey];
          if (previousTtl !== undefined && previousTtl !== p.ttl) {
            asymmetricRouteAnomalies.push({
              srcIp: p.srcIp,
              dstIp: p.dstIp,
              srcPort: p.srcPort,
              dstPort: p.dstPort,
              firstFlagObserved: 'TTL Shift',
              ipId: p.ipId,
              ttlValue: p.ttl,
              detail: `Time-To-Live (TTL) hop count fluctuated from ${previousTtl} to ${p.ttl} mid-stream inside the connection flow, confirming that subsequent packets traversed an altered layer-3 routing path.`,
              verdict: 'Asymmetric Return Path detected. Firewall will drop this flow as invalid state.',
              timestamp: p.timestamp
            });
          }
          tcpFlowTtls[connKey] = p.ttl;
        }

        // Retransmission if we've seen this exact connection sending the same sequence number with length > 0,
        // or a duplicate SYN / FIN.
        if (len > 0 || isSyn || isFin) {
          if (!tcpSequences[connKey]) {
            tcpSequences[connKey] = [];
          }

          // Check if we've seen this sequence number before
          const matchingPastSeq = tcpSequences[connKey].find(
            (past) => past.seq === seq && past.len === len
          );

          if (matchingPastSeq) {
            // Check time difference. If they are extremely close, it might be a duplicated capture packet.
            // But if it's > 5ms or has actual TCP characteristics, it's a retransmission.
            p.isRetransmission = true;
            result.retransmissionCount++;
            flows[flowKey].retransmissions++;
            p.info = `[TCP Retransmission] ` + p.info;
          } else {
            tcpSequences[connKey].push({ seq, len, ts: p.timestamp });
          }
        }

        // Perform Duplicate ACK Check
        // ACKs travel on the reverse connection, so check what the last ACK on the active forward connection is.
        if (p.tcpFlags?.ack && !p.tcpFlags?.syn && !p.tcpFlags?.fin && len === 0) {
          const ackNum = p.tcpAck ?? 0;
          const winSize = p.length; // use length to distinguish window updates
          
          if (!tcpLastAck[connKey]) {
            tcpLastAck[connKey] = { ack: ackNum, win: winSize, count: 1 };
          } else {
            const last = tcpLastAck[connKey];
            if (last.ack === ackNum) {
              last.count++;
              if (last.count >= 3) {
                p.isDuplicateAck = true;
                result.duplicateAckCount++;
                p.info = `[TCP Dup ACK #${last.count - 1}] ` + p.info;
              }
            } else {
              // New sequence has been ACKed, reset tracker
              tcpLastAck[connKey] = { ack: ackNum, win: winSize, count: 1 };
            }
          }
        }

        // --- Calculate Round-Trip Time (RTT) ---
        // 1. If it consumes sequence space (len > 0, SYN, FIN), log it as an outstanding segment
        if (len > 0 || isSyn || isFin) {
          const expectedAck = seq + (len > 0 ? len : 1);
          if (!outstandingTcpSegments[connKey]) {
            outstandingTcpSegments[connKey] = [];
          }
          outstandingTcpSegments[connKey].push({ expectedAck, ts: p.timestamp });
        }

        // 2. If it has ACK flag, check reverse outstanding segments
        if (p.tcpFlags?.ack) {
          const ackNum = p.tcpAck ?? 0;
          const reverseConnKey = `${p.dstIp}:${p.dstPort} -> ${p.srcIp}:${p.srcPort}`;
          const list = outstandingTcpSegments[reverseConnKey];
          if (list && list.length > 0) {
            const idx = list.findIndex((item) => item.expectedAck === ackNum);
            if (idx !== -1) {
              const match = list[idx];
              const rtt = p.timestamp - match.ts;
              if (rtt > 0 && rtt < 10000) {
                p.rtt = rtt;
                rttValues.push(rtt);
                p.info = p.info + ` [RTT=${rtt.toFixed(1)}ms]`;
              }
              // Clean matched and older acknowledged segments
              outstandingTcpSegments[reverseConnKey] = list.slice(idx + 1);
            }
          }
        }

        // --- Calculate Handshake RTT (SYN-ACK - SYN) ---
        if (isSyn) {
          if (!p.tcpFlags?.ack) {
            // Client SYN
            handshakeSynTime[connKey] = p.timestamp;
          } else {
            // Server SYN-ACK
            const reverseKey = `${p.dstIp}:${p.dstPort} -> ${p.srcIp}:${p.srcPort}`;
            if (handshakeSynTime[reverseKey] !== undefined) {
              const handshakeRtt = p.timestamp - handshakeSynTime[reverseKey];
              if (handshakeRtt > 0 && handshakeRtt < 10000) {
                handshakeRtts.push(handshakeRtt);
              }
            }
          }
        }

        // --- Calculate Server Time-To-First-Byte (TTFB) ---
        if (p.protocol === 'HTTP') {
          const isRequest = p.dstPort === 80 || p.dstPort === 8080 || p.info.includes('GET ') || p.info.includes('POST ');
          const isResponse = p.srcPort === 80 || p.srcPort === 8080 || p.info.includes('HTTP/');
          if (isRequest) {
            httpRequestTime[connKey] = p.timestamp;
          } else if (isResponse) {
            const reverseKey = `${p.dstIp}:${p.dstPort} -> ${p.srcIp}:${p.srcPort}`;
            if (httpRequestTime[reverseKey] !== undefined) {
              const ttfb = p.timestamp - httpRequestTime[reverseKey];
              if (ttfb > 0 && ttfb < 10000) {
                serverTtfbs.push(ttfb);
              }
              delete httpRequestTime[reverseKey]; // measure only time to FIRST byte/response packet
            }
          }
        }

        // --- Collect Standard Non-RST TTLs or Perform RST Fingerprinting ---
        const isRst = p.tcpFlags?.rst ?? false;
        if (!isRst) {
          if (p.ttl !== undefined) {
            if (!ipStandardTtls[p.srcIp]) {
              ipStandardTtls[p.srcIp] = new Set<number>();
            }
            ipStandardTtls[p.srcIp].add(p.ttl);
          }
        } else {
          const rstTtl = p.ttl ?? 0;
          const standardTtls = Array.from(ipStandardTtls[p.srcIp] || []);
          let isMiddlebox = false;
          if (standardTtls.length > 0) {
            for (const sttl of standardTtls) {
              if (Math.abs(rstTtl - sttl) >= 4 && (rstTtl === 64 || rstTtl === 128 || rstTtl === 255)) {
                isMiddlebox = true;
                break;
              }
            }
          } else {
            if (rstTtl === 64 || rstTtl === 128 || rstTtl === 255) {
              isMiddlebox = true;
            }
          }

          const verdict = isMiddlebox ? 'Terminated By: Inline Security Device / Firewall' : 'Endpoint Application Crash (Socket Abort)';
          const baselineStr = standardTtls.length > 0 ? standardTtls.join(', ') : 'None';
          const ttlDeltaCheck = standardTtls.length > 0 ? `Data TTL: ${baselineStr} vs RST TTL: ${rstTtl}` : `Isolated RST (TTL: ${rstTtl})`;

          rstFingerprints.push({
            srcIp: p.srcIp,
            dstIp: p.dstIp,
            srcPort: p.srcPort,
            dstPort: p.dstPort,
            rstTtl,
            standardTtls,
            ttlDeltaCheck,
            verdict,
            timestamp: p.timestamp
          });
        }

        // --- TLS Handshake SNI and Fatal Alert Parsing Flow ---
        const streamKey = `${p.srcIp}:${p.srcPort} <-> ${p.dstIp}:${p.dstPort}`;
        const reverseStreamKey = `${p.dstIp}:${p.dstPort} <-> ${p.srcIp}:${p.srcPort}`;

        if (p.tlsSni) {
          tlsStreamSni[streamKey] = p.tlsSni;
          tlsStreamSni[reverseStreamKey] = p.tlsSni;
        }

        if (p.tlsAlertCode !== undefined) {
          const code = p.tlsAlertCode;
          const sni = tlsStreamSni[streamKey] || tlsStreamSni[reverseStreamKey] || 'Unknown/IP-Direct';
          
          const alertMap: Record<number, { name: string; explanation: string }> = {
            40: { name: "Handshake Failure", explanation: "Cipher mismatch or negotiation failure. The client and server do not share mutually supported cipher suites or TLS extensions." },
            48: { name: "Unknown CA", explanation: "Certificate validation failed. The client rejected the server's certificate because it was signed by an untrusted or self-signed Certificate Authority." },
            49: { name: "Access Denied", explanation: "Inbound/Outbound connection blocked. Access has been explicitly denied (often indicative of inline proxy decryption blocking or client certificate rejection)." },
            70: { name: "Protocol Version Unsupported", explanation: "Legacy TLS Version Rejected. The client attempted to negotiate an insecure TLS version (such as TLS 1.0 or 1.1) which has been disabled server-side." }
          };
          const mapped = alertMap[code] || { name: `Alert ${code}`, explanation: "Generic unmapped TLS fatal connection tear down alert." };

          tlsAlerts.push({
            srcIp: p.srcIp,
            dstIp: p.dstIp,
            srcPort: p.srcPort,
            dstPort: p.dstPort,
            sni,
            alertCode: code,
            alertName: mapped.name,
            explanation: mapped.explanation,
            timestamp: p.timestamp,
            streamId: p.tcpSeq || p.index
          });
        }
      }

      // Check for ICMP Redirect messages indicating route changes
      if (p.protocol === 'ICMP' && p.info.includes('Redirect')) {
        asymmetricRouteAnomalies.push({
          srcIp: p.srcIp,
          dstIp: p.dstIp,
          firstFlagObserved: 'ICMP Redirect',
          ipId: p.ipId,
          ttlValue: p.ttl,
          detail: `ICMP Redirect message broadcasted. An intermediate gateway router is proactively directing the client host to route its traffic through an alternate path, forcing asymmetry.`,
          verdict: 'Asymmetric Return Path detected. Firewall will drop this flow as invalid state.',
          timestamp: p.timestamp
        });
      }
    }

    // DNS Failure Check
    if (p.protocol === 'DNS' && p.dnsQuery) {
      if (p.dnsQuery.isResponse && (p.dnsQuery.rcode === 2 || p.dnsQuery.rcode === 3)) {
        result.dnsFailureCount++;
        result.dnsAnomalies.push(p);
      }
    }

    // Security Plaintext Credential Check
    if (p.plaintextCredentials) {
      result.plaintextCredentialsCount++;
      result.plaintextCredentials.push(p);
    }

    // Track TTL values if present
    if (p.srcIp && p.srcIp !== 'Unknown' && p.ttl !== undefined) {
      if (!ipTtls[p.srcIp]) {
        ipTtls[p.srcIp] = { ttls: new Set<number>(), packetCount: 0 };
      }
      ipTtls[p.srcIp].ttls.add(p.ttl);
      ipTtls[p.srcIp].packetCount++;
    }
  });

  // Calculate Global Retransmission Rate
  if (result.totalTcpPackets > 0) {
    result.globalRetransmissionRate = (result.retransmissionCount / result.totalTcpPackets) * 100;
  }

  // Analyze TTLs for potential anomalies (asymmetric routing or spoofing)
  const ttlAnomalies: TtlAnomaly[] = [];
  Object.entries(ipTtls).forEach(([ip, data]) => {
    const ttlsArray = Array.from(data.ttls);
    if (ttlsArray.length > 1) {
      const minTtl = Math.min(...ttlsArray);
      const maxTtl = Math.max(...ttlsArray);
      const delta = maxTtl - minTtl;

      let type: TtlAnomaly['type'] = 'Asymmetric Routing';
      let description = `IP source is arriving with fluctuating TTL hops (observed TTLs: ${ttlsArray.join(', ')}). This indicates that packets are traversing different numbers of layer-3 router hops, confirming asymmetric network paths.`;

      if (delta >= 15) {
        type = 'Possible IP Spoofing';
        description = `Critical TTL variance detected (observed TTLs: ${ttlsArray.join(', ')}). The base stack TTL started from completely different baselines (e.g., Linux 64 vs Windows 128), indicating potential malicious IP Spoofing or spoofed traffic injections on the local subnet.`;
      }

      ttlAnomalies.push({
        ip,
        ttls: ttlsArray,
        type,
        packetCount: data.packetCount,
        description
      });
    }

    const hasRoutingLoop = ttlsArray.some(t => t <= 3 && t > 0);
    if (hasRoutingLoop && !ttlAnomalies.some(a => a.ip === ip)) {
      ttlAnomalies.push({
        ip,
        ttls: ttlsArray,
        type: 'Routing Loop',
        packetCount: data.packetCount,
        description: `Extremely low TTL observed (TTLs: ${ttlsArray.join(', ')}). Packets are expiring near-hops (TTL <= 3), indicating a layer-3 network routing loop or proactive traceroute scanning.`
      });
    }
  });
  result.ttlAnomalies = ttlAnomalies;

  // Finalize Connections Summaries
  const connections: NetworkFlow[] = Object.entries(flows).map(([key, f]) => {
    const [srcIp, dstIp] = key.split(' -> ');
    return {
      srcIp,
      dstIp,
      totalPackets: f.totalPackets,
      totalBytes: f.totalBytes,
      tcpPackets: f.tcpPackets,
      retransmissions: f.retransmissions,
      retransmissionRate: f.tcpPackets > 0 ? (f.retransmissions / f.tcpPackets) * 100 : 0
    };
  }).sort((a, b) => b.retransmissions - a.retransmissions);

  result.connections = connections;

  // Finalize Capture Profiler Data
  const averageFrameSize = result.totalPackets > 0 ? result.totalBytes / result.totalPackets : 0;
  
  const protocolBreakdown = Object.entries(result.protocolCounts).map(([proto, count]) => {
    const bytes = protocolBytes[proto] || 0;
    const percentage = result.totalPackets > 0 ? (count / result.totalPackets) * 100 : 0;
    return { protocol: proto, count, bytes, percentage };
  }).sort((a, b) => b.count - a.count);

  const commonTcpWindowSizes = Object.entries(windowSizeCounts).map(([size, count]) => {
    const percentage = result.totalTcpPackets > 0 ? (count / result.totalTcpPackets) * 100 : 0;
    return { windowSize: parseInt(size), count, percentage };
  }).sort((a, b) => b.count - a.count).slice(0, 5);

  const maxFrameSize = packets.length > 0 ? Math.max(...packets.map(p => p.length)) : 0;
  let possibleMtuIssue = false;
  let mtuDescription = "MTU settings appear healthy. Maximum frame size is within standard 1500-byte Ethernet bounds, and no fragment-related path degradation was detected.";

  if (maxFrameSize > 1500) {
    possibleMtuIssue = true;
    mtuDescription = `Warning: Jumbo frames detected (max size: ${maxFrameSize}B). Standard Ethernet MTU limit is 1500B. If intermediate switches or firewalls on this path do not have Jumbo frames enabled, they will drop these packets, causing severe TCP retransmissions and application timing-out issues.`;
  } else if (result.retransmissionCount > 10 && maxFrameSize === 1500) {
    possibleMtuIssue = true;
    mtuDescription = `Note: Large frames at the 1500B MTU boundary are experiencing severe TCP retransmissions. This indicates a potential Path MTU Discovery (PMTUD) blackhole on an intermediate router, where packets exceeding a path bottleneck are dropped without ICMP Destination Unreachable/Fragmentation Needed replies. Recommend configuring TCP MSS Clamping to 1420-1440B.`;
  }

  result.captureProfiler = {
    averageFrameSize,
    protocolBreakdown,
    commonTcpWindowSizes,
    mtuAnalysis: {
      maxFrameSize,
      possibleMtuIssue,
      description: mtuDescription
    }
  };

  // Finalize RTT statistics
  if (rttValues.length > 0) {
    const sum = rttValues.reduce((a, b) => a + b, 0);
    result.averageRtt = sum / rttValues.length;
    result.maxRtt = Math.max(...rttValues);
    result.rttPacketsCount = rttValues.length;
  } else {
    result.averageRtt = 0;
    result.maxRtt = 0;
    result.rttPacketsCount = 0;
  }

  // Finalize Handshake RTT
  if (handshakeRtts.length > 0) {
    const sum = handshakeRtts.reduce((a, b) => a + b, 0);
    result.averageHandshakeRtt = sum / handshakeRtts.length;
    result.handshakeRttCount = handshakeRtts.length;
  } else {
    // fall back to general RTT if no handshake packets parsed
    result.averageHandshakeRtt = result.averageRtt || 0;
    result.handshakeRttCount = 0;
  }

  // Finalize HTTP TTFB
  if (serverTtfbs.length > 0) {
    const sum = serverTtfbs.reduce((a, b) => a + b, 0);
    result.averageTtfb = sum / serverTtfbs.length;
    result.ttfbPacketsCount = serverTtfbs.length;
  } else {
    result.averageTtfb = 0;
    result.ttfbPacketsCount = 0;
  }

  // Finalize RST Fingerprints
  result.rstFingerprints = rstFingerprints;

  // Finalize TLS alerts
  result.tlsAlerts = tlsAlerts;

  // Finalize Asymmetric Routing Anomalies
  result.asymmetricRouteAnomalies = asymmetricRouteAnomalies;

  // Pass to Passive OS & Shadow IoT Fingerprinting
  const devicesMap: Record<string, {
    ip: string;
    inferredOs: FingerprintedDevice['inferredOs'];
    ttl: number;
    windowSize: number;
    mss?: number;
    windowScale?: number;
    sackPermitted: boolean;
    packetCount: number;
    isRogue: boolean;
    subnetStatus: FingerprintedDevice['subnetStatus'];
    destinationsReached: Set<string>;
  }> = {};

  packets.forEach((p) => {
    if (p.srcIp && p.srcIp !== 'Unknown') {
      if (!devicesMap[p.srcIp]) {
        devicesMap[p.srcIp] = {
          ip: p.srcIp,
          inferredOs: 'Unknown/Generic',
          ttl: p.ttl || 64,
          windowSize: p.tcpWindowSize || 1024,
          mss: p.tcpOptions?.mss,
          windowScale: p.tcpOptions?.windowScale,
          sackPermitted: p.tcpOptions?.sackPermitted ?? false,
          packetCount: 0,
          isRogue: false,
          subnetStatus: 'Nominal',
          destinationsReached: new Set<string>()
        };
      }

      const dev = devicesMap[p.srcIp];
      dev.packetCount++;
      if (p.dstIp && p.dstIp !== 'Unknown') {
        dev.destinationsReached.add(p.dstIp);
      }

      // Perform SYN-based fingerprinting
      if (p.tcpFlags?.syn) {
        dev.ttl = p.ttl || dev.ttl;
        dev.windowSize = p.tcpWindowSize || dev.windowSize;
        if (p.tcpOptions) {
          if (p.tcpOptions.mss !== undefined) dev.mss = p.tcpOptions.mss;
          if (p.tcpOptions.windowScale !== undefined) dev.windowScale = p.tcpOptions.windowScale;
          if (p.tcpOptions.sackPermitted !== undefined) dev.sackPermitted = p.tcpOptions.sackPermitted;
        }

        const t = dev.ttl;
        const w = dev.windowSize;
        const hasScale = dev.windowScale !== undefined;
        const hasSack = dev.sackPermitted;

        if (t === 128 || (t > 64 && t <= 128)) {
          dev.inferredOs = 'Windows';
        } else if (t === 64 || (t > 32 && t <= 64)) {
          dev.inferredOs = 'Linux/Android';
        } else if (t === 255 || (w > 0 && w <= 4096 && !hasScale && !hasSack)) {
          dev.inferredOs = 'Rogue Embedded IoT System (RTOS)';
        }
      }

      // Check for security alerts (protected subnet breach)
      // Embedded IoT Stack reaching secure DB ports or database subnets
      if (dev.inferredOs === 'Rogue Embedded IoT System (RTOS)') {
        const hasBreached = Array.from(dev.destinationsReached).some(dst => {
          return dst.startsWith('10.0.1.') || dst.startsWith('10.0.2.') || p.dstPort === 3306 || p.dstPort === 5432 || p.dstPort === 443;
        });
        if (hasBreached) {
          dev.isRogue = true;
          dev.subnetStatus = 'Protected Subnet Breach';
        }
      }
    }
  });

  const fingerprintedDevices: FingerprintedDevice[] = Object.values(devicesMap).map(dev => ({
    ip: dev.ip,
    inferredOs: dev.inferredOs,
    ttl: dev.ttl,
    windowSize: dev.windowSize,
    mss: dev.mss,
    windowScale: dev.windowScale,
    sackPermitted: dev.sackPermitted,
    packetCount: dev.packetCount,
    isRogue: dev.isRogue,
    subnetStatus: dev.subnetStatus,
    destinationsReached: Array.from(dev.destinationsReached)
  }));

  result.fingerprintedDevices = fingerprintedDevices;

  // Pass to Collect RADIUS Access Rejections
  const collectedRadiusRejects: RadiusReject[] = [];
  packets.forEach((p) => {
    if (p.radiusData && p.radiusData.code === 3) {
      collectedRadiusRejects.push({
        timestamp: p.timestamp,
        userName: p.radiusData.userName || 'Unknown User',
        nasIp: p.dstIp,
        nasPort: p.srcPort,
        respondingIamIp: p.srcIp,
        replyMessage: p.radiusData.replyMessage || 'Access explicitly rejected by server policy.',
        eapMessage: p.radiusData.eapMessage
      });
    }
  });
  result.radiusRejects = collectedRadiusRejects;

  // Collect BGP notifications and OSPF MTU mismatches
  const collectedBgpNotifications: BgpNotification[] = [];
  const ospfMtusPerIp: Record<string, { routerId: string; mtu: number; ts: number }> = {};
  const ospfMismatches: OspfMismatch[] = [];

  packets.forEach((p) => {
    // 1. Process BGP notification
    if (p.protocol === 'BGP' && p.bgpData && p.bgpData.type === 3) {
      const code = p.bgpData.errorCode || 0;
      const subcode = p.bgpData.errorSubcode || 0;
      const details = getBgpErrorDetails(code, subcode);
      collectedBgpNotifications.push({
        timestamp: p.timestamp,
        srcIp: p.srcIp,
        dstIp: p.dstIp,
        srcPort: p.srcPort || 179,
        dstPort: p.dstPort || 179,
        errorCode: code,
        errorName: details.errorName,
        subcode: subcode,
        subcodeName: details.subcodeName,
        detail: details.detail
      });
    }

    // 2. Process OSPF MTU tracking
    if (p.protocol === 'OSPF' && p.ospfData && p.ospfData.type === 2 && p.ospfData.ospfMtu !== undefined) {
      ospfMtusPerIp[p.srcIp] = {
        routerId: p.ospfData.routerId,
        mtu: p.ospfData.ospfMtu,
        ts: p.timestamp
      };
    }
  });

  // Now, check for mismatches between any observed communicators
  const checkedPairs = new Set<string>();
  packets.forEach((p) => {
    if (p.protocol === 'OSPF' && p.ospfData && p.ospfData.type === 2) {
      const ipA = p.srcIp;
      const ipB = p.dstIp;
      const pairKey1 = `${ipA}-${ipB}`;
      const pairKey2 = `${ipB}-${ipA}`;

      if (!checkedPairs.has(pairKey1) && !checkedPairs.has(pairKey2)) {
        checkedPairs.add(pairKey1);
        const peerA = ospfMtusPerIp[ipA];
        const peerB = ospfMtusPerIp[ipB];

        if (peerA && peerB && peerA.mtu !== peerB.mtu) {
          ospfMismatches.push({
            timestamp: Math.max(peerA.ts, peerB.ts),
            srcIp: ipA,
            dstIp: ipB,
            router1Mtu: peerA.mtu,
            router2Mtu: peerB.mtu,
            detail: `OSPF Neighbor MTU Negotiation conflict identified. Router ID ${peerA.routerId} (IP: ${ipA}) is advertising Interface MTU=${peerA.mtu} B, while Router ID ${peerB.routerId} (IP: ${ipB}) is advertising Interface MTU=${peerB.mtu} B.`,
            verdict: 'OSPF MTU Mismatch Detected - Adjacency Stuck in EXSTART/EXCHANGE'
          });
        }
      }
    }
  });

  result.bgpNotifications = collectedBgpNotifications;
  result.ospfMismatches = ospfMismatches;

  // 3. Process VoIP & Telephony Analysis (SIP Calls & RTP Audio Streams)
  const sipCallsMap = new Map<string, {
    callId: string;
    caller: string;
    callee: string;
    status: string;
    statusCode?: number;
    method?: string;
    isFailed: boolean;
    failureReason?: string;
    startTime: number;
    endTime: number;
    srcIp: string;
    dstIp: string;
    messagesCount: number;
  }>();

  packets.forEach((p) => {
    if (p.sipData) {
      const cid = p.sipData.callId;
      let call = sipCallsMap.get(cid);
      if (!call) {
        call = {
          callId: cid,
          caller: p.sipData.from || 'Anonymous',
          callee: p.sipData.to || 'Unknown',
          status: p.sipData.isResponse ? `${p.sipData.statusCode} ${p.sipData.statusText}` : `${p.sipData.method} (Initiated)`,
          statusCode: p.sipData.statusCode,
          method: p.sipData.method,
          isFailed: false,
          startTime: p.timestamp,
          endTime: p.timestamp,
          srcIp: p.srcIp,
          dstIp: p.dstIp,
          messagesCount: 0
        };
        sipCallsMap.set(cid, call);
      }

      call.messagesCount++;
      call.endTime = Math.max(call.endTime, p.timestamp);

      if (p.sipData.from && p.sipData.from !== 'Anonymous') {
        call.caller = p.sipData.from;
      }
      if (p.sipData.to && p.sipData.to !== 'Unknown') {
        call.callee = p.sipData.to;
      }

      if (p.sipData.isResponse && p.sipData.statusCode !== undefined) {
        const code = p.sipData.statusCode;
        // Specifically flag 4xx (Client Error), 5xx (Server Error), and 6xx (Global Failure)
        if (code >= 400 && code <= 699) {
          call.isFailed = true;
          call.statusCode = code;
          call.status = `${code} ${p.sipData.statusText || 'Failed'}`;
          if (code >= 400 && code < 500) {
            call.failureReason = `4xx Client Error (${code} ${p.sipData.statusText || 'Rejected'})`;
          } else if (code >= 500 && code < 600) {
            call.failureReason = `5xx Server Error (${code} ${p.sipData.statusText || 'Gateway Failure'})`;
          } else {
            call.failureReason = `6xx Global Failure (${code} ${p.sipData.statusText || 'Decline'})`;
          }
        } else if (!call.isFailed) {
          call.statusCode = code;
          call.status = `${code} ${p.sipData.statusText || 'OK'}`;
        }
      }
    }
  });

  const calls: SipCall[] = Array.from(sipCallsMap.values()).map(c => ({
    ...c,
    durationMs: Math.max(0, c.endTime - c.startTime)
  }));

  // Analyze RTP streams by SSRC
  const rtpStreamsMap = new Map<number, {
    ssrc: number;
    srcIp: string;
    dstIp: string;
    srcPort: number;
    dstPort: number;
    payloadType: number;
    payloadName: string;
    sequences: number[];
    timestamps: number[];
    arrivalTimes: number[];
  }>();

  packets.forEach((p) => {
    if (p.rtpData) {
      const ssrc = p.rtpData.ssrc;
      let stream = rtpStreamsMap.get(ssrc);
      if (!stream) {
        stream = {
          ssrc,
          srcIp: p.srcIp,
          dstIp: p.dstIp,
          srcPort: p.srcPort || 0,
          dstPort: p.dstPort || 0,
          payloadType: p.rtpData.payloadType,
          payloadName: p.rtpData.payloadName,
          sequences: [],
          timestamps: [],
          arrivalTimes: []
        };
        rtpStreamsMap.set(ssrc, stream);
      }
      stream.sequences.push(p.rtpData.sequenceNumber);
      stream.timestamps.push(p.rtpData.timestamp);
      stream.arrivalTimes.push(p.timestamp);
    }
  });

  const rtpStreams: RtpStream[] = Array.from(rtpStreamsMap.values()).map(s => {
    const received = s.sequences.length;
    let expected = received;
    let lost = 0;
    let lossPercent = 0;

    if (received > 1) {
      const sortedSeqs = [...s.sequences].sort((a, b) => a - b);
      const minSeq = sortedSeqs[0];
      const maxSeq = sortedSeqs[sortedSeqs.length - 1];
      expected = Math.max(received, maxSeq - minSeq + 1);
      lost = Math.max(0, expected - received);
      lossPercent = expected > 0 ? (lost / expected) * 100 : 0;
    }

    // Estimate RFC 3550 interarrival jitter
    let jitter = 0;
    for (let i = 1; i < s.arrivalTimes.length; i++) {
      const transitD = (s.arrivalTimes[i] - s.arrivalTimes[i - 1]) - ((s.timestamps[i] - s.timestamps[i - 1]) / 8);
      const absD = Math.abs(transitD);
      jitter = jitter + (absD - jitter) / 16;
    }

    let qualityVerdict: RtpStream['qualityVerdict'] = 'Nominal (< 1% Loss)';
    if (lossPercent >= 10.0) {
      qualityVerdict = 'Critical Audio Drop / Unintelligible (> 10% Loss)';
    } else if (lossPercent >= 3.0) {
      qualityVerdict = 'Severe Jitter & Robotic Audio (3-10% Loss)';
    } else if (lossPercent >= 1.0) {
      qualityVerdict = 'Mild Jitter (1-3% Loss)';
    }

    return {
      ssrc: s.ssrc,
      ssrcHex: `0x${s.ssrc.toString(16).toUpperCase()}`,
      srcIp: s.srcIp,
      dstIp: s.dstIp,
      srcPort: s.srcPort,
      dstPort: s.dstPort,
      payloadType: s.payloadType,
      payloadName: s.payloadName,
      packetsReceived: received,
      packetsExpected: expected,
      packetsLost: lost,
      packetLossPercent: Number(lossPercent.toFixed(1)),
      jitterMs: Number(Math.max(0.5, jitter).toFixed(1)),
      qualityVerdict
    };
  });

  const failedCallsCount = calls.filter(c => c.isFailed).length;
  const maxRtpPacketLossPercent = rtpStreams.length > 0
    ? Math.max(...rtpStreams.map(s => s.packetLossPercent))
    : 0;

  const totalJitter = rtpStreams.reduce((acc, s) => acc + s.jitterMs, 0);
  const averageJitterMs = rtpStreams.length > 0 ? Number((totalJitter / rtpStreams.length).toFixed(1)) : 0;

  result.voipAnalysis = {
    calls,
    rtpStreams,
    totalCalls: calls.length,
    failedCallsCount,
    maxRtpPacketLossPercent,
    averageJitterMs,
    hasSevereDegradation: maxRtpPacketLossPercent >= 3.0 || failedCallsCount > 0
  };

  // Limit packets shown in table to first 400 for React UI speed
  result.packets = packets.slice(0, 400);

  return result;
};
