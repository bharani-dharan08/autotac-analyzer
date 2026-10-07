/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { Buffer } from 'buffer';

class PcapWriter {
  private chunks: Buffer[] = [];

  constructor() {
    const globalHeader = Buffer.alloc(24);
    globalHeader.writeUInt32LE(0xa1b2c3d4, 0); // Magic (Microseconds)
    globalHeader.writeUInt16LE(2, 4);          // Major version 2
    globalHeader.writeUInt16LE(4, 6);          // Minor version 4
    globalHeader.writeUInt32LE(0, 8);          // Timezone (GMT)
    globalHeader.writeUInt32LE(0, 12);         // Accuracy
    globalHeader.writeUInt32LE(65535, 16);     // Snaplen
    globalHeader.writeUInt32LE(1, 20);         // Link Type: Ethernet (1)
    this.chunks.push(globalHeader);
  }

  addPacket(timestampMs: number, packetBytes: Buffer) {
    const header = Buffer.alloc(16);
    const sec = Math.floor(timestampMs / 1000);
    const usec = Math.floor((timestampMs % 1000) * 1000);
    header.writeUInt32LE(sec, 0);
    header.writeUInt32LE(usec, 4);
    header.writeUInt32LE(packetBytes.length, 8);  // incl_len
    header.writeUInt32LE(packetBytes.length, 12); // orig_len
    this.chunks.push(header);
    this.chunks.push(packetBytes);
  }

  toBuffer(): Buffer {
    return Buffer.concat(this.chunks);
  }
}

const buildEthernetHeader = (srcMac: string, dstMac: string, etherType: number): Buffer => {
  const eth = Buffer.alloc(14);
  const parseMac = (mac: string) => mac.split(':').map(x => parseInt(x, 16));
  const dstMacBytes = parseMac(dstMac);
  const srcMacBytes = parseMac(srcMac);
  for (let i = 0; i < 6; i++) {
    eth[i] = dstMacBytes[i];
    eth[6 + i] = srcMacBytes[i];
  }
  eth.writeUInt16BE(etherType, 12);
  return eth;
};

const buildIpHeader = (srcIp: string, dstIp: string, protocol: number, payloadLen: number, id: number, ttl: number = 64): Buffer => {
  const ip = Buffer.alloc(20);
  ip[0] = 0x45; // Version 4, IHL 5 (20 bytes)
  ip[1] = 0x00; // DSCP/ECN
  ip.writeUInt16BE(20 + payloadLen, 2); // Total Length
  ip.writeUInt16BE(id, 4); // ID
  ip.writeUInt16BE(0x4000, 6); // Flags: Don't Fragment
  ip[8] = ttl; // TTL
  ip[9] = protocol; // 6 = TCP, 17 = UDP
  ip.writeUInt16BE(0, 10); // Header Checksum

  const parseIp = (ipStr: string) => ipStr.split('.').map(Number);
  const srcBytes = parseIp(srcIp);
  const dstBytes = parseIp(dstIp);
  for (let i = 0; i < 4; i++) {
    ip[12 + i] = srcBytes[i];
    ip[16 + i] = dstBytes[i];
  }
  return ip;
};

const buildUdpHeader = (srcPort: number, dstPort: number, payloadLen: number): Buffer => {
  const udp = Buffer.alloc(8);
  udp.writeUInt16BE(srcPort, 0);
  udp.writeUInt16BE(dstPort, 2);
  udp.writeUInt16BE(payloadLen + 8, 4);
  udp.writeUInt16BE(0, 6);
  return udp;
};

const buildTcpHeader = (
  srcPort: number,
  dstPort: number,
  seq: number,
  ack: number,
  flags: { syn?: boolean; ack?: boolean; fin?: boolean; rst?: boolean; psh?: boolean },
  payloadLen: number
): Buffer => {
  const tcp = Buffer.alloc(20);
  tcp.writeUInt16BE(srcPort, 0);
  tcp.writeUInt16BE(dstPort, 2);
  tcp.writeUInt32BE(seq, 4);
  tcp.writeUInt32BE(ack, 8);
  tcp[12] = 0x50; // Data Offset: 5 (20 bytes)
  
  let f = 0;
  if (flags.fin) f |= 0x01;
  if (flags.syn) f |= 0x02;
  if (flags.rst) f |= 0x04;
  if (flags.psh) f |= 0x08;
  if (flags.ack) f |= 0x10;
  tcp[13] = f;

  tcp.writeUInt16BE(64240, 14); // Window Size
  tcp.writeUInt16BE(0, 16);     // Checksum
  tcp.writeUInt16BE(0, 18);     // Urgent pointer
  return tcp;
};

const buildDnsPayload = (domain: string, isResponse: boolean, rcode: number, transactionId: number, dnsTtl: number = 300): Buffer => {
  const dnsHeader = Buffer.alloc(12);
  dnsHeader.writeUInt16BE(transactionId, 0);
  
  let flags = isResponse ? 0x8180 : 0x0100;
  if (isResponse) {
    flags |= (rcode & 0x0f);
  }
  dnsHeader.writeUInt16BE(flags, 2);
  dnsHeader.writeUInt16BE(1, 4); // Questions = 1
  dnsHeader.writeUInt16BE(isResponse && rcode === 0 ? 1 : 0, 6); // Answers = 1 if NoError response
  dnsHeader.writeUInt16BE(0, 8);
  dnsHeader.writeUInt16BE(0, 10);

  const labels = domain.split('.');
  const labelBuffers: Buffer[] = [];
  labels.forEach(lbl => {
    const b = Buffer.alloc(1 + lbl.length);
    b[0] = lbl.length;
    b.write(lbl, 1, 'ascii');
    labelBuffers.push(b);
  });
  const terminator = Buffer.from([0]);
  const qTypeClass = Buffer.alloc(4);
  qTypeClass.writeUInt16BE(1, 0); // Type A (1)
  qTypeClass.writeUInt16BE(1, 2); // Class IN (1)

  let ansBuffer = Buffer.alloc(0);
  if (isResponse && rcode === 0) {
    // Basic Answer Record
    ansBuffer = Buffer.alloc(16);
    ansBuffer.writeUInt16BE(0xc00c, 0); // Pointer to Domain Name at offset 12
    ansBuffer.writeUInt16BE(1, 2);      // Type A
    ansBuffer.writeUInt16BE(1, 4);      // Class IN
    ansBuffer.writeUInt32BE(dnsTtl, 6);    // TTL
    ansBuffer.writeUInt16BE(4, 10);     // RDLength = 4
    ansBuffer[12] = 192; ansBuffer[13] = 168; ansBuffer[14] = 2; ansBuffer[15] = 100; // Result IP 192.168.2.100
  }

  return Buffer.concat([dnsHeader, ...labelBuffers, terminator, qTypeClass, ansBuffer]);
};

export const addSimulatedVoipTraffic = (
  writer: PcapWriter,
  baseTimestamp: number,
  clientMac: string,
  serverMac: string,
  startingIpId: number = 7000
) => {
  let ipId = startingIpId;
  const addSipPacket = (
    srcIp: string,
    dstIp: string,
    srcPort: number,
    dstPort: number,
    sipPayload: string,
    deltaMs: number,
    isTcp: boolean = false
  ) => {
    const payloadBuf = Buffer.from(sipPayload, 'ascii');
    const ethHeader = buildEthernetHeader(clientMac, serverMac, 0x0800);
    let transportHeader: Buffer;
    let ipHeader: Buffer;

    if (!isTcp) {
      transportHeader = buildUdpHeader(srcPort, dstPort, payloadBuf.length);
      ipHeader = buildIpHeader(srcIp, dstIp, 17, transportHeader.length + payloadBuf.length, ipId++, 64);
    } else {
      transportHeader = buildTcpHeader(srcPort, dstPort, 1000 + deltaMs, 2000, { psh: true, ack: true }, payloadBuf.length);
      ipHeader = buildIpHeader(srcIp, dstIp, 6, transportHeader.length + payloadBuf.length, ipId++, 64);
    }

    writer.addPacket(baseTimestamp + deltaMs, Buffer.concat([ethHeader, ipHeader, transportHeader, payloadBuf]));
  };

  const addRtpPacket = (
    srcIp: string,
    dstIp: string,
    srcPort: number,
    dstPort: number,
    seq: number,
    rtpTs: number,
    ssrc: number,
    pt: number = 0,
    deltaMs: number = 0
  ) => {
    const rtpHeader = Buffer.alloc(12);
    rtpHeader[0] = 0x80; // V=2, P=0, X=0, CC=0
    rtpHeader[1] = pt & 0x7f; // M=0, PT (0 = PCMU)
    rtpHeader.writeUInt16BE(seq, 2);
    rtpHeader.writeUInt32BE(rtpTs, 4);
    rtpHeader.writeUInt32BE(ssrc, 8);

    const audioSamples = Buffer.alloc(160, 0xd5); // 20ms G.711u audio sample frame
    const udpPayload = Buffer.concat([rtpHeader, audioSamples]);
    const ethHeader = buildEthernetHeader(clientMac, serverMac, 0x0800);
    const udpHeader = buildUdpHeader(srcPort, dstPort, udpPayload.length);
    const ipHeader = buildIpHeader(srcIp, dstIp, 17, udpHeader.length + udpPayload.length, ipId++, 64);

    writer.addPacket(baseTimestamp + deltaMs, Buffer.concat([ethHeader, ipHeader, udpHeader, udpPayload]));
  };

  // 1. SIP Call #1: Alice to Bob (Nominal Session, but downstream RTP suffers Severe Packet Loss & Jitter)
  const callId1 = 'call-101-sales-9482@10.0.1.10';
  addSipPacket(
    '10.0.1.10', '10.0.2.20', 5060, 5060,
    `INVITE sip:bob@10.0.2.20 SIP/2.0\r\nVia: SIP/2.0/UDP 10.0.1.10:5060\r\nFrom: "Alice (Sales Exec)" <sip:1001@10.0.1.10>;tag=991201\r\nTo: "Bob (Tech Support)" <sip:2002@10.0.2.20>\r\nCall-ID: ${callId1}\r\nCSeq: 1 INVITE\r\nContact: <sip:1001@10.0.1.10:5060>\r\nContent-Type: application/sdp\r\n\r\n`,
    400
  );
  addSipPacket(
    '10.0.2.20', '10.0.1.10', 5060, 5060,
    `SIP/2.0 100 Trying\r\nVia: SIP/2.0/UDP 10.0.1.10:5060\r\nFrom: "Alice (Sales Exec)" <sip:1001@10.0.1.10>;tag=991201\r\nTo: "Bob (Tech Support)" <sip:2002@10.0.2.20>\r\nCall-ID: ${callId1}\r\nCSeq: 1 INVITE\r\n\r\n`,
    410
  );
  addSipPacket(
    '10.0.2.20', '10.0.1.10', 5060, 5060,
    `SIP/2.0 180 Ringing\r\nVia: SIP/2.0/UDP 10.0.1.10:5060\r\nFrom: "Alice (Sales Exec)" <sip:1001@10.0.1.10>;tag=991201\r\nTo: "Bob (Tech Support)" <sip:2002@10.0.2.20>\r\nCall-ID: ${callId1}\r\nCSeq: 1 INVITE\r\n\r\n`,
    430
  );
  addSipPacket(
    '10.0.2.20', '10.0.1.10', 5060, 5060,
    `SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP 10.0.1.10:5060\r\nFrom: "Alice (Sales Exec)" <sip:1001@10.0.1.10>;tag=991201\r\nTo: "Bob (Tech Support)" <sip:2002@10.0.2.20>\r\nCall-ID: ${callId1}\r\nCSeq: 1 INVITE\r\nContact: <sip:2002@10.0.2.20:5060>\r\n\r\n`,
    460
  );
  addSipPacket(
    '10.0.1.10', '10.0.2.20', 5060, 5060,
    `ACK sip:bob@10.0.2.20 SIP/2.0\r\nVia: SIP/2.0/UDP 10.0.1.10:5060\r\nFrom: "Alice (Sales Exec)" <sip:1001@10.0.1.10>;tag=991201\r\nTo: "Bob (Tech Support)" <sip:2002@10.0.2.20>\r\nCall-ID: ${callId1}\r\nCSeq: 1 ACK\r\n\r\n`,
    470
  );

  // RTP Stream for Call #1 (SSRC: 0x38AF2910) - Audio degradation with missing sequence numbers!
  const ssrc1 = 0x38AF2910;
  const droppedSeqs = new Set([1004, 1005, 1008, 1012, 1017, 1018, 1022]); // 7 dropped packets out of 25 -> 28% loss!
  let rtpTs1 = 160000;
  for (let seq = 1000; seq <= 1024; seq++) {
    rtpTs1 += 160;
    if (!droppedSeqs.has(seq)) {
      addRtpPacket('10.0.1.10', '10.0.2.20', 16400, 16400, seq, rtpTs1, ssrc1, 0, 500 + (seq - 1000) * 20);
    }
  }

  // 2. SIP Call #2: Charlie to Conf Bridge -> 486 Busy Here (Client Error)
  const callId2 = 'call-202-conf-88192@10.0.1.15';
  addSipPacket(
    '10.0.1.15', '10.0.2.50', 5060, 5060,
    `INVITE sip:bridge@10.0.2.50 SIP/2.0\r\nVia: SIP/2.0/UDP 10.0.1.15:5060\r\nFrom: "Charlie (Operations)" <sip:1005@10.0.1.15>;tag=38210\r\nTo: "Conference Bridge" <sip:8000@10.0.2.50>\r\nCall-ID: ${callId2}\r\nCSeq: 1 INVITE\r\n\r\n`,
    600
  );
  addSipPacket(
    '10.0.2.50', '10.0.1.15', 5060, 5060,
    `SIP/2.0 486 Busy Here\r\nVia: SIP/2.0/UDP 10.0.1.15:5060\r\nFrom: "Charlie (Operations)" <sip:1005@10.0.1.15>;tag=38210\r\nTo: "Conference Bridge" <sip:8000@10.0.2.50>\r\nCall-ID: ${callId2}\r\nCSeq: 1 INVITE\r\nReason: Q.850;cause=17;text="User Busy"\r\n\r\n`,
    630
  );
  addSipPacket(
    '10.0.1.15', '10.0.2.50', 5060, 5060,
    `ACK sip:bridge@10.0.2.50 SIP/2.0\r\nVia: SIP/2.0/UDP 10.0.1.15:5060\r\nFrom: "Charlie (Operations)" <sip:1005@10.0.1.15>;tag=38210\r\nTo: "Conference Bridge" <sip:8000@10.0.2.50>\r\nCall-ID: ${callId2}\r\nCSeq: 1 ACK\r\n\r\n`,
    640
  );

  // 3. SIP Call #3: David to SBC Trunk -> 503 Service Unavailable (Server Error)
  const callId3 = 'call-303-trunk-outage@10.0.1.18';
  addSipPacket(
    '10.0.1.18', '10.0.2.1', 5060, 5060,
    `INVITE sip:9110@10.0.2.1 SIP/2.0\r\nVia: SIP/2.0/UDP 10.0.1.18:5060\r\nFrom: "David (Billing)" <sip:1008@10.0.1.18>;tag=55912\r\nTo: "Gateway-SBC Trunk" <sip:9110@10.0.2.1>\r\nCall-ID: ${callId3}\r\nCSeq: 1 INVITE\r\n\r\n`,
    700
  );
  addSipPacket(
    '10.0.2.1', '10.0.1.18', 5060, 5060,
    `SIP/2.0 503 Service Unavailable\r\nVia: SIP/2.0/UDP 10.0.1.18:5060\r\nFrom: "David (Billing)" <sip:1008@10.0.1.18>;tag=55912\r\nTo: "Gateway-SBC Trunk" <sip:9110@10.0.2.1>\r\nCall-ID: ${callId3}\r\nCSeq: 1 INVITE\r\nReason: SIP;cause=503;text="All B-Channels Exhausted / License Exceeded"\r\n\r\n`,
    750
  );
  addSipPacket(
    '10.0.1.18', '10.0.2.1', 5060, 5060,
    `ACK sip:9110@10.0.2.1 SIP/2.0\r\nVia: SIP/2.0/UDP 10.0.1.18:5060\r\nFrom: "David (Billing)" <sip:1008@10.0.1.18>;tag=55912\r\nTo: "Gateway-SBC Trunk" <sip:9110@10.0.2.1>\r\nCall-ID: ${callId3}\r\nCSeq: 1 ACK\r\n\r\n`,
    760
  );

  // 4. SIP Call #4: External Carrier to Desk -> 603 Decline (Global Failure)
  const callId4 = 'call-404-carrier-decl@carrier.sip.net';
  addSipPacket(
    '198.51.100.25', '10.0.2.100', 5060, 5060,
    `INVITE sip:4040@10.0.2.100 SIP/2.0\r\nVia: SIP/2.0/UDP 198.51.100.25:5060\r\nFrom: "External Carrier" <sip:+14155552671@carrier.sip.net>;tag=7712\r\nTo: "IT Desk" <sip:4040@10.0.2.100>\r\nCall-ID: ${callId4}\r\nCSeq: 1 INVITE\r\n\r\n`,
    800
  );
  addSipPacket(
    '10.0.2.100', '198.51.100.25', 5060, 5060,
    `SIP/2.0 603 Decline\r\nVia: SIP/2.0/UDP 198.51.100.25:5060\r\nFrom: "External Carrier" <sip:+14155552671@carrier.sip.net>;tag=7712\r\nTo: "IT Desk" <sip:4040@10.0.2.100>\r\nCall-ID: ${callId4}\r\nCSeq: 1 INVITE\r\nReason: SIP;cause=603;text="Do Not Disturb / Global Policy Block"\r\n\r\n`,
    830
  );

  // 5. RTP Stream #2: Nominal Voice Call (SSRC: 0x55EE11AA) - 0% loss baseline
  const ssrc2 = 0x55EE11AA;
  let rtpTs2 = 240000;
  for (let seq = 2000; seq <= 2024; seq++) {
    rtpTs2 += 160;
    addRtpPacket('10.0.1.25', '10.0.2.40', 17000, 17000, seq, rtpTs2, ssrc2, 0, 900 + (seq - 2000) * 20);
  }
};

export const generateScenarioPcap = (scenarioId: string): Buffer => {
  const writer = new PcapWriter();
  const startTime = Date.now() - 300000; // 5 minutes ago
  let ipId = 1000;

  const clientMac = '00:11:22:33:44:55';
  const serverMac = '00:50:56:c0:00:08';

  if (scenarioId === 'congestion_retransmission') {
    // SCENARIO 1: Enterprise Congestion & Retransmission
    // Simulates an application client 10.0.0.5 connecting to a database 192.168.1.10 on postgres 5432.
    // Experiences heavy packet loss (approx 20% retransmissions) and multiple Duplicate ACKs.
    const clientIp = '10.0.0.5';
    const serverIp = '192.168.1.10';
    const clientPort = 49215;
    const serverPort = 5432;

    let clientSeq = 100;
    let serverSeq = 2000;
    let timestamp = startTime;

    const addTcpPacket = (
      fromClient: boolean,
      flags: { syn?: boolean; ack?: boolean; fin?: boolean; rst?: boolean; psh?: boolean },
      payloadStr: string,
      customSeq?: number,
      customAck?: number
    ) => {
      const srcIp = fromClient ? clientIp : serverIp;
      const dstIp = fromClient ? serverIp : clientIp;
      const srcPort = fromClient ? clientPort : serverPort;
      const dstPort = fromClient ? serverPort : clientPort;
      const srcM = fromClient ? clientMac : serverMac;
      const dstM = fromClient ? serverMac : clientMac;

      const payload = payloadStr ? Buffer.from(payloadStr, 'utf8') : Buffer.alloc(0);
      const seqVal = customSeq !== undefined ? customSeq : (fromClient ? clientSeq : serverSeq);
      const ackVal = customAck !== undefined ? customAck : (fromClient ? serverSeq : clientSeq);

      const tcpHeader = buildTcpHeader(srcPort, dstPort, seqVal, ackVal, flags, payload.length);
      
      let pktTtl = 64;
      if (!fromClient && customSeq !== undefined) {
        pktTtl = 52; // Asymmetric failover path (12 extra hops)
      }
      
      const ipHeader = buildIpHeader(srcIp, dstIp, 6, tcpHeader.length + payload.length, ipId++, pktTtl);
      const ethHeader = buildEthernetHeader(srcM, dstM, 0x0800);

      const fullPacket = Buffer.concat([ethHeader, ipHeader, tcpHeader, payload]);
      writer.addPacket(timestamp, fullPacket);

      // Advance seq numbers if not custom sequence (retransmission)
      if (customSeq === undefined) {
        let size = payload.length;
        if (flags.syn || flags.fin) size += 1;
        if (fromClient) {
          clientSeq += size;
        } else {
          serverSeq += size;
        }
      }
      timestamp += 100 + Math.floor(Math.random() * 50); // advance time
    };

    // 1. Handshake
    addTcpPacket(true, { syn: true }, '');
    addTcpPacket(false, { syn: true, ack: true }, '');
    addTcpPacket(true, { ack: true }, '');

    // 2. Client sends query
    addTcpPacket(true, { ack: true, psh: true }, 'SELECT * FROM patients WHERE id = 45293;');

    // 3. Server receives query, starts sending data rows
    // Send normal database packet
    addTcpPacket(false, { ack: true, psh: true }, 'PatientInfoRow: Ash Sivasamy | ID: 45293 | Status: Outpatient');

    // 4. Client acknowledges normal data packet
    addTcpPacket(true, { ack: true }, '');

    // 5. Server sends a major chunk of binary query results, but client packet drops!
    // Server tries to send block #1
    const serverSeqBeforeDrop = serverSeq;
    addTcpPacket(false, { ack: true, psh: true }, 'PatientMedicationRecord_Chunk1: [Penicillin, Ibuprofen, Saline]');

    // 6. Server sends block #2, but client hasn't received block #1!
    // Since client missed block #1, it continues sending ACKs expecting block #1
    // Let's increment server sequence normally for block #2
    const block1Len = 60; // Approximate payload length
    addTcpPacket(false, { ack: true, psh: true }, 'PatientMedicationRecord_Chunk2: [Dosage: 500mg, Interval: 8h]');

    // Client responds with a Duplicate ACK (noting it is still waiting for serverSeqBeforeDrop)
    addTcpPacket(true, { ack: true }, '', clientSeq, serverSeqBeforeDrop); // Dup ACK 1

    // Server sends block #3
    addTcpPacket(false, { ack: true, psh: true }, 'PatientMedicationRecord_Chunk3: [Assigned_MD: Dr. House, Dept: ER]');

    // Client responds with another Duplicate ACK
    addTcpPacket(true, { ack: true }, '', clientSeq, serverSeqBeforeDrop); // Dup ACK 2
    addTcpPacket(true, { ack: true }, '', clientSeq, serverSeqBeforeDrop); // Dup ACK 3

    // 7. Server Retransmits block #1 due to Duplicate ACKs / TimeOut!
    // Same sequence number as serverSeqBeforeDrop
    addTcpPacket(false, { ack: true, psh: true }, 'PatientMedicationRecord_Chunk1: [Penicillin, Ibuprofen, Saline]', serverSeqBeforeDrop, clientSeq);

    // 8. Client finally receives the missing piece and acknowledges everything up to current serverSeq
    addTcpPacket(true, { ack: true }, '');

    // 9. Let's add multiple consecutive drops to inflate the retransmission statistics to show as severe
    for (let i = 0; i < 6; i++) {
      const dropSeq = serverSeq;
      addTcpPacket(false, { ack: true, psh: true }, `PatientBillingRecord_LineItem_${i}: [Charge: $250.00, Code: 99214]`);
      // Simulating a packet loss, server retransmits it
      timestamp += 200; // long timeout
      addTcpPacket(false, { ack: true, psh: true }, `PatientBillingRecord_LineItem_${i}: [Charge: $250.00, Code: 99214]`, dropSeq, clientSeq);
      addTcpPacket(true, { ack: true }, '');
    }

    // 10. Connection Tear Down
    addTcpPacket(true, { fin: true, ack: true }, '');
    addTcpPacket(false, { fin: true, ack: true }, '');
    addTcpPacket(true, { ack: true }, '');

    // Add VoIP & SIP/RTP Streams to enterprise congestion capture
    addSimulatedVoipTraffic(writer, timestamp, clientMac, serverMac);

  } else if (scenarioId === 'dns_outage') {
    // SCENARIO 2: DNS Server Outages
    // Emulates a client 192.168.2.15 resolving external API hosts using primary 192.168.2.1 and secondary 8.8.8.8.
    // DNS requests get RCODE=2 (ServFail) and RCODE=3 (NXDomain) because the internal DNS server daemon crashed, and the secondary firewall rules are blocking UDP 53 external.
    const clientIp = '192.168.2.15';
    const primaryDnsIp = '192.168.2.1';
    const secondaryDnsIp = '8.8.8.8';
    
    let timestamp = startTime;
    let txId = 2000;

    const addDnsPacket = (dnsServerIp: string, domain: string, isResponse: boolean, rcode: number, dnsTtl: number = 300) => {
      const srcIp = isResponse ? dnsServerIp : clientIp;
      const dstIp = isResponse ? clientIp : dnsServerIp;
      const srcPort = isResponse ? 53 : 51234;
      const dstPort = isResponse ? 51234 : 53;
      const srcM = isResponse ? serverMac : clientMac;
      const dstM = isResponse ? clientMac : serverMac;

      const dnsPayload = buildDnsPayload(domain, isResponse, rcode, txId, dnsTtl);
      const udpHeader = buildUdpHeader(srcPort, dstPort, dnsPayload.length);
      const ipHeader = buildIpHeader(srcIp, dstIp, 17, udpHeader.length + dnsPayload.length, ipId++);
      const ethHeader = buildEthernetHeader(srcM, dstM, 0x0800);

      const fullPacket = Buffer.concat([ethHeader, ipHeader, udpHeader, dnsPayload]);
      writer.addPacket(timestamp, fullPacket);

      if (isResponse) {
        txId++; // next transaction
      }
      timestamp += 50 + Math.floor(Math.random() * 50);
    };

    // DNS Query #1: Successful local address lookup
    addDnsPacket(primaryDnsIp, 'intranet.hospital-internal.local', false, 0);
    addDnsPacket(primaryDnsIp, 'intranet.hospital-internal.local', true, 0); // NoError (0)

    // DNS Query #2: Failed Database Replica lookup (returns NXDomain / Name Error)
    addDnsPacket(primaryDnsIp, 'patients-db-replica.hospital-internal.local', false, 0);
    addDnsPacket(primaryDnsIp, 'patients-db-replica.hospital-internal.local', true, 3); // NXDomain (3)

    // DNS Query #3: Primary Server Crash / Service Failure (returns ServFail)
    addDnsPacket(primaryDnsIp, 'api.payment-gateway.com', false, 0);
    addDnsPacket(primaryDnsIp, 'api.payment-gateway.com', true, 2); // ServFail (2)

    // DNS Query #4: Client attempts secondary server 8.8.8.8, but secondary server is down or blocked
    // The request times out, or the secondary firewall drops it and returns a failure
    addDnsPacket(secondaryDnsIp, 'api.payment-gateway.com', false, 0);
    timestamp += 1000; // simulated timeout wait
    addDnsPacket(secondaryDnsIp, 'api.payment-gateway.com', true, 2); // ServFail (2)

    // Add 4 more failed queries for other endpoints to build stats
    addDnsPacket(primaryDnsIp, 'auth-service.hospital-internal.local', false, 0);
    addDnsPacket(primaryDnsIp, 'auth-service.hospital-internal.local', true, 3); // NXDomain

    addDnsPacket(primaryDnsIp, 'telemetry.cloud-provider.com', false, 0);
    addDnsPacket(primaryDnsIp, 'telemetry.cloud-provider.com', true, 2); // ServFail

    // DNS Query #5: Suspicious low-TTL query (potential DNS hijacking / evasion)
    addDnsPacket(primaryDnsIp, 'security-update.evasion-fastflux.net', false, 0);
    addDnsPacket(primaryDnsIp, 'security-update.evasion-fastflux.net', true, 0, 2); // NoError with custom TTL = 2s!

    // BGP Peering Failure Simulation (Hold Timer Expired)
    const addBgpNotificationPacket = (srcIp: string, dstIp: string, errCode: number, errSubcode: number) => {
      const ethHeader = buildEthernetHeader(clientMac, serverMac, 0x0800);
      
      const bgpPayload = Buffer.alloc(21);
      bgpPayload.fill(0xff, 0, 16); // Marker
      bgpPayload.writeUInt16BE(21, 16); // Length
      bgpPayload[18] = 3; // Message Type: NOTIFICATION
      bgpPayload[19] = errCode;
      bgpPayload[20] = errSubcode;

      const tcpHeader = buildTcpHeader(179, 179, 1200, 2400, { ack: true, psh: true }, bgpPayload.length);
      const ipHeader = buildIpHeader(srcIp, dstIp, 6, tcpHeader.length + bgpPayload.length, ipId++, 64);

      const fullPacket = Buffer.concat([ethHeader, ipHeader, tcpHeader, bgpPayload]);
      writer.addPacket(timestamp + 100, fullPacket);
    };

    // OSPF MTU Negotiation Failure Simulation (MTU Mismatch)
    const addOspfDbdPacket = (srcIp: string, dstIp: string, routerIdIp: string, mtuVal: number) => {
      const ethHeader = buildEthernetHeader(clientMac, serverMac, 0x0800);

      // OSPFv2 Header (24 bytes) + DBD fields (8 bytes) = 32 bytes
      const ospfPacket = Buffer.alloc(32);
      ospfPacket[0] = 2; // Version
      ospfPacket[1] = 2; // Type: DBD
      ospfPacket.writeUInt16BE(32, 2); // Length
      
      // Router ID
      const rIdParts = routerIdIp.split('.').map(Number);
      ospfPacket[4] = rIdParts[0]; ospfPacket[5] = rIdParts[1]; ospfPacket[6] = rIdParts[2]; ospfPacket[7] = rIdParts[3];

      // DBD payload fields
      ospfPacket.writeUInt16BE(mtuVal, 24); // Interface MTU
      ospfPacket[26] = 0x02; // Options
      ospfPacket[27] = 0x03; // Flags (I, M, MS)
      ospfPacket.writeUInt32BE(12345, 28); // DD Seq Number

      const ipHeader = buildIpHeader(srcIp, dstIp, 89, ospfPacket.length, ipId++, 64);

      const fullPacket = Buffer.concat([ethHeader, ipHeader, ospfPacket]);
      writer.addPacket(timestamp + 200, fullPacket);
    };

    // Simulating BGP peering hold timer expiry between two core routers
    addBgpNotificationPacket('192.168.100.1', '192.168.100.2', 4, 0); // Hold Timer Expired

    // Simulating OSPF adjacency negotiation MTU mismatch between two neighbors
    addOspfDbdPacket('10.255.0.1', '10.255.0.2', '1.1.1.1', 1500); // Router 1 uses 1500B
    addOspfDbdPacket('10.255.0.2', '10.255.0.1', '2.2.2.2', 1492); // Router 2 uses 1492B (Mismatch!)
  } else if (scenarioId === 'plaintext_credentials') {
    // SCENARIO 3: SOC Threat Analysis - Plaintext Credentials
    // Simulated attacker or negligent user at 172.16.5.42 connecting to an insecure dashboard 10.10.1.100.
    // Transmits raw unencrypted Basic Auth, HTTP POST credentials, and FTP USER/PASS logins.
    const clientIp = '172.16.5.42';
    const serverIp = '10.10.1.100';
    const clientPort = 58210;
    const httpPort = 80;
    const ftpPort = 21;

    let seq = 3000;
    let ack = 5000;
    let timestamp = startTime;

    const addTcpPayload = (dstPort: number, payloadStr: string, customTtl: number = 54) => {
      const isHttp = dstPort === 80;
      const srcP = isHttp ? clientPort : clientPort + 1; // separate connection
      const dstP = dstPort;

      const payload = Buffer.from(payloadStr, 'utf8');
      const tcpHeader = buildTcpHeader(srcP, dstP, seq, ack, { ack: true, psh: true }, payload.length);
      const ipHeader = buildIpHeader(clientIp, serverIp, 6, tcpHeader.length + payload.length, ipId++, customTtl);
      const ethHeader = buildEthernetHeader(clientMac, serverMac, 0x0800);

      const fullPacket = Buffer.concat([ethHeader, ipHeader, tcpHeader, payload]);
      writer.addPacket(timestamp, fullPacket);

      seq += payload.length;
      timestamp += 200;
    };

    // 1. HTTP Basic Authorization leak
    const httpBasicPayload = 
      "GET /admin/dashboard HTTP/1.1\r\n" +
      "Host: 10.10.1.100\r\n" +
      "User-Agent: Mozilla/5.0\r\n" +
      "Authorization: Basic YWRtaW46c3VwZXJzZWNyZXQxMjM=\r\n" + // admin:supersecret123
      "Accept: */*\r\n\r\n";
    addTcpPayload(httpPort, httpBasicPayload, 54);

    // 2. HTTP POST Insecure login form parameters leak
    const httpFormPayload = 
      "POST /login.php HTTP/1.1\r\n" +
      "Host: 10.10.1.100\r\n" +
      "Content-Type: application/x-www-form-urlencoded\r\n" +
      "Content-Length: 46\r\n\r\n" +
      "username=secadmin&password=Password999!&submit=Login";
    addTcpPayload(httpPort, httpFormPayload, 54);

    // 3. FTP Plaintext login leak
    addTcpPayload(ftpPort, "USER ftp_operator\r\n", 54);
    addTcpPayload(ftpPort, "PASS FtpPassWord777!\r\n", 54);
    addTcpPayload(ftpPort, "SYST\r\n", 54);
    addTcpPayload(ftpPort, "PORT 172,16,5,42,227,90\r\n", 54);
    addTcpPayload(ftpPort, "LIST\r\n", 54);

    // 4. Injected Firewall Reset (RST) Packet Simulation
    // Standard data packets from 172.16.5.42 had TTL = 54. 
    // An inline Palo Alto Firewall detects the FTP LIST command of sensitive directories and injects an RST with TTL = 64.
    const rstTcpHeader = buildTcpHeader(clientPort + 1, ftpPort, seq, ack, { rst: true }, 0);
    const rstIpHeader = buildIpHeader(clientIp, serverIp, 6, rstTcpHeader.length, ipId++, 64);
    const rstEthHeader = buildEthernetHeader(clientMac, serverMac, 0x0800);
    const rstPacket = Buffer.concat([rstEthHeader, rstIpHeader, rstTcpHeader]);
    writer.addPacket(timestamp, rstPacket);

    // 5. Standard Socket Abort / Crash Reset Simulation
    // A standard application crash socket abort occurs on the HTTP session where the socket is terminated locally,
    // so the RST packet TTL is exactly the same as the standard packets (54).
    const abortTcpHeader = buildTcpHeader(clientPort, httpPort, seq, ack, { rst: true }, 0);
    const abortIpHeader = buildIpHeader(clientIp, serverIp, 6, abortTcpHeader.length, ipId++, 54);
    const abortEthHeader = buildEthernetHeader(clientMac, serverMac, 0x0800);
    const abortPacket = Buffer.concat([rstEthHeader, abortIpHeader, abortTcpHeader]);
    writer.addPacket(timestamp + 50, abortPacket);

    // 6. Simulated TLS Handshake Failures (Fatal Alert Diagnostics)
    // Flow #1: Client trying to connect to api.payment-gateway.com on port 443 (HTTPS)
    // Server rejects with Alert Code 40: Handshake Failure (Cipher mismatch)
    const tlsClientPort1 = 59001;
    const tlsClientPort2 = 59002;
    const httpsPort = 443;

    const addTlsFailure = (domain: string, alertCode: number, clientPortVal: number) => {
      const ethHeader = buildEthernetHeader(clientMac, serverMac, 0x0800);
      const serverEthHeader = buildEthernetHeader(serverMac, clientMac, 0x0800);

      // Client sends Client Hello containing the domain SNI
      const clientHello = Buffer.alloc(45 + domain.length);
      clientHello[0] = 0x16; // Content-Type: Handshake
      clientHello[1] = 0x03; clientHello[2] = 0x03; // Version: TLS 1.2 (0x0303)
      clientHello.writeUInt16BE(40 + domain.length, 3); // Record Length
      clientHello[5] = 0x01; // Handshake Type: Client Hello
      clientHello.write(domain, 40, 'ascii'); // Write plain domain near the end so regex extracts it!

      const clientHeader = buildTcpHeader(clientPortVal, httpsPort, 1000, 2000, { ack: true, psh: true }, clientHello.length);
      const clientIpHeader = buildIpHeader(clientIp, serverIp, 6, clientHeader.length + clientHello.length, ipId++, 64);
      const clientPacket = Buffer.concat([ethHeader, clientIpHeader, clientHeader, clientHello]);
      writer.addPacket(timestamp + 100, clientPacket);

      // Server responds with TLS Alert Code
      // Content Type = 21 (Alert), Version = 0x0303, Length = 2, Payload = [Fatal (2), Alert Code]
      const serverAlert = Buffer.alloc(7);
      serverAlert[0] = 0x15; // Content-Type: Alert
      serverAlert[1] = 0x03; serverAlert[2] = 0x03; // Version
      serverAlert.writeUInt16BE(2, 3); // Length
      serverAlert[5] = 0x02; // Level: Fatal (2)
      serverAlert[6] = alertCode; // Alert Code

      const serverHeader = buildTcpHeader(httpsPort, clientPortVal, 2000, 1000 + clientHello.length, { ack: true, psh: true }, serverAlert.length);
      const serverIpHeader = buildIpHeader(serverIp, clientIp, 6, serverHeader.length + serverAlert.length, ipId++, 64);
      const serverPacket = Buffer.concat([serverEthHeader, serverIpHeader, serverHeader, serverAlert]);
      writer.addPacket(timestamp + 150, serverPacket);
    };

    addTlsFailure('api.payment-gateway.com', 40, tlsClientPort1); // Handshake Failure (Cipher mismatch)
    addTlsFailure('legacy-checkout.old-domain.org', 70, tlsClientPort2); // Protocol Version Unsupported (TLS 1.0 Rejected)

    // Simulated Cloud Overlay (VXLAN & GENEVE) Decapsulation Diagnostics
    // 1. VXLAN Tunnel: Outer 10.200.1.10 -> 10.200.1.20, Inner 172.31.22.4 -> 10.0.1.50 (Unencrypted HTTP)
    const addVxlanSimulatedPacket = (outerSrc: string, outerDst: string, innerSrc: string, innerDst: string, innerPort: number, payloadStr: string) => {
      const ethHeader = buildEthernetHeader(clientMac, serverMac, 0x0800);
      
      const innerPayload = Buffer.from(payloadStr, 'utf8');
      const innerTcp = buildTcpHeader(49152, innerPort, 500, 600, { ack: true, psh: true }, innerPayload.length);
      const innerIp = buildIpHeader(innerSrc, innerDst, 6, innerTcp.length + innerPayload.length, ipId++, 64);
      const innerEth = buildEthernetHeader('00:aa:bb:cc:dd:ee', '00:aa:bb:cc:dd:ff', 0x0800);
      const innerFrame = Buffer.concat([innerEth, innerIp, innerTcp, innerPayload]);

      // VXLAN Header (8 bytes)
      const vxlanHeader = Buffer.alloc(8);
      vxlanHeader[0] = 0x08; // I flag set
      vxlanHeader.writeUInt32BE(12345 << 8, 4); // VNI = 12345 in 24 bits

      const udpHeader = buildUdpHeader(4789, 4789, vxlanHeader.length + innerFrame.length);
      const ipHeader = buildIpHeader(outerSrc, outerDst, 17, udpHeader.length + vxlanHeader.length + innerFrame.length, ipId++, 64);

      const fullPacket = Buffer.concat([ethHeader, ipHeader, udpHeader, vxlanHeader, innerFrame]);
      writer.addPacket(timestamp + 200, fullPacket);
    };

    // 2. GENEVE Tunnel: Outer 10.200.1.15 -> 10.200.1.25, Inner 172.31.50.8 -> 10.0.2.90 (Encrypted TLS)
    const addGeneveSimulatedPacket = (outerSrc: string, outerDst: string, innerSrc: string, innerDst: string, innerPort: number, payloadStr: string) => {
      const ethHeader = buildEthernetHeader(clientMac, serverMac, 0x0800);

      const innerPayload = Buffer.from(payloadStr, 'utf8');
      const innerTcp = buildTcpHeader(49153, innerPort, 700, 800, { ack: true, psh: true }, innerPayload.length);
      const innerIp = buildIpHeader(innerSrc, innerDst, 6, innerTcp.length + innerPayload.length, ipId++, 64);
      const innerEth = buildEthernetHeader('00:aa:bb:cc:dd:ee', '00:aa:bb:cc:dd:ff', 0x0800);
      const innerFrame = Buffer.concat([innerEth, innerIp, innerTcp, innerPayload]);

      // GENEVE Header (8 bytes)
      const geneveHeader = Buffer.alloc(8);
      geneveHeader[0] = 0x00; // Ver = 0, OptLen = 0
      geneveHeader.writeUInt16BE(0x6558, 2); // Protocol Type: Transparent Ethernet Bridging
      geneveHeader.writeUInt32BE(54321 << 8, 4); // VNI = 54321 in 24-bits

      const udpHeader = buildUdpHeader(6081, 6081, geneveHeader.length + innerFrame.length);
      const ipHeader = buildIpHeader(outerSrc, outerDst, 17, udpHeader.length + geneveHeader.length + innerFrame.length, ipId++, 64);

      const fullPacket = Buffer.concat([ethHeader, ipHeader, udpHeader, geneveHeader, innerFrame]);
      writer.addPacket(timestamp + 300, fullPacket);
    };

    addVxlanSimulatedPacket(
      '10.200.1.10', '10.200.1.20',
      '172.31.22.4', '10.0.1.50',
      80,
      'GET /api/v1/health HTTP/1.1\r\nHost: insecure-app-api.internal\r\n\r\n'
    );

    addGeneveSimulatedPacket(
      '10.200.1.15', '10.200.1.25',
      '172.31.50.8', '10.0.2.90',
      443,
      'TLS handshake record client_hello snippet content'
    );

    // SIMULATED VOIP & SIP/RTP STREAMS
    addSimulatedVoipTraffic(writer, timestamp, clientMac, serverMac);
  } else if (scenarioId === 'voip_telephony') {
    // SCENARIO 4: Enterprise VoIP Quality & Telephony Diagnostics
    addSimulatedVoipTraffic(writer, startTime, clientMac, serverMac);
  }

  return writer.toBuffer();
};
