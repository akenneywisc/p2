import java.net.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.*;
import java.util.*;
import java.io.*;

public class TCPend {

    static long dataBytes = 0;
    static long packetCount = 0;
    static long outOfSeq = 0;
    static long checksumDiscards = 0;
    static long retransmissions = 0;
    static long dupAcks = 0;
    static long startTime;

    static void logPacket(String dir, boolean syn, boolean ack, boolean fin,
                          int dataLen, int seq, int ackNum, long startNs) {
        double t = (System.nanoTime() - startNs) / 1e9;
        System.out.printf("%s %.3f %s %s %s %s %d %d %d%n",
                dir, t,
                syn ? "S" : "-",
                ack ? "A" : "-",
                fin ? "F" : "-",
                dataLen > 0 ? "D" : "-",
                seq, dataLen, ackNum);
    }

    static boolean checkCheckSum(byte[] bytes) {
        short stored = (short) (((bytes[22] & 0xFF) << 8) | (bytes[23] & 0xFF));
        return stored == TCPSegment.getChecksum(bytes);
    }

    static void sendSegment(DatagramSocket socket, TCPSegment seg,
                            InetAddress addr, int port) throws Exception {
        byte[] bytes = seg.compose();
        socket.send(new DatagramPacket(bytes, bytes.length, addr, port));
        logPacket("snd", seg.synFlag, seg.ackFlag, seg.finFlag,
                seg.dataLen, seg.seqNum, seg.ackNum, startTime);
        packetCount++;
    }

    static long[] senderHandshake(DatagramSocket socket,
                                   InetAddress remoteAddr, int remotePort,
                                   int mtu) throws Exception {
        long timeoutNs = 5_000_000_000L;
        socket.setSoTimeout(5000);
        int synRetries = 0;
        long estimatedRTT = 0, estimatedDeviation = 0;

        outer:
        while (true) {
            TCPSegment syn = new TCPSegment();
            syn.seqNum = 0;
            syn.synFlag = true;
            syn.timestamp = System.nanoTime();
            sendSegment(socket, syn, remoteAddr, remotePort);

            while (true) {
                try {
                    byte[] buf = new byte[24 + mtu];
                    DatagramPacket dp = new DatagramPacket(buf, buf.length);
                    socket.receive(dp);
                    byte[] recv = Arrays.copyOf(dp.getData(), dp.getLength());
                    if (!checkCheckSum(recv)) { checksumDiscards++; continue; }

                    TCPSegment seg = TCPSegment.decompose(recv);
                    logPacket("rcv", seg.synFlag, seg.ackFlag, seg.finFlag,
                            seg.dataLen, seg.seqNum, seg.ackNum, startTime);

                    if (seg.synFlag && seg.ackFlag && seg.ackNum == 1) {
                        estimatedRTT = System.nanoTime() - seg.timestamp;
                        estimatedDeviation = 0;
                        timeoutNs = 2 * estimatedRTT;
                        break outer;
                    }
                } catch (SocketTimeoutException e) {
                    synRetries++;
                    if (synRetries > 16) {
                        System.err.println("SYN retransmit limit exceeded");
                        socket.close();
                        System.exit(1);
                    }
                    retransmissions++;
                    break;
                }
            }
        }

        TCPSegment ack = new TCPSegment();
        ack.seqNum = 1;
        ack.ackNum = 1;
        ack.ackFlag = true;
        ack.timestamp = System.nanoTime();
        sendSegment(socket, ack, remoteAddr, remotePort);

        socket.setSoTimeout(Math.max(1, (int) (timeoutNs / 1_000_000)));
        return new long[]{estimatedRTT, estimatedDeviation, timeoutNs};
    }

    static Object[] receiverHandshake(DatagramSocket socket, int mtu) throws Exception {
        byte[] synAckBytes = null;
        InetAddress senderAddr = null;
        int senderPort = -1;

        while (true) {
            byte[] buf = new byte[24 + mtu];
            DatagramPacket dp = new DatagramPacket(buf, buf.length);
            socket.receive(dp);
            byte[] recv = Arrays.copyOf(dp.getData(), dp.getLength());
            if (!checkCheckSum(recv)) { checksumDiscards++; continue; }

            TCPSegment seg = TCPSegment.decompose(recv);
            if (seg.synFlag && seg.seqNum == 0) {
                logPacket("rcv", true, seg.ackFlag, false, 0, 0, seg.ackNum, startTime);
                packetCount++;
                senderAddr = dp.getAddress();
                senderPort = dp.getPort();

                TCPSegment synAck = new TCPSegment();
                synAck.seqNum = 0;
                synAck.ackNum = 1;
                synAck.synFlag = true;
                synAck.ackFlag = true;
                synAck.timestamp = seg.timestamp;
                synAckBytes = synAck.compose();
                socket.send(new DatagramPacket(synAckBytes, synAckBytes.length, senderAddr, senderPort));
                logPacket("snd", true, true, false, 0, 0, 1, startTime);
                packetCount++;
                break;
            }
        }

        while (true) {
            byte[] buf = new byte[24 + mtu];
            DatagramPacket dp = new DatagramPacket(buf, buf.length);
            socket.receive(dp);
            byte[] recv = Arrays.copyOf(dp.getData(), dp.getLength());
            if (!checkCheckSum(recv)) { checksumDiscards++; continue; }

            TCPSegment seg = TCPSegment.decompose(recv);
            if (seg.synFlag && seg.seqNum == 0) {
                logPacket("rcv", true, seg.ackFlag, false, 0, 0, seg.ackNum, startTime);
                socket.send(new DatagramPacket(synAckBytes, synAckBytes.length, senderAddr, senderPort));
                logPacket("snd", true, true, false, 0, 0, 1, startTime);
                continue;
            }
            if (seg.ackFlag && seg.ackNum == 1) {
                logPacket("rcv", false, true, false, seg.dataLen, seg.seqNum, seg.ackNum, startTime);
                packetCount++;
                break;
            }
        }

        return new Object[]{senderAddr, senderPort};
    }

    static void senderTeardown(DatagramSocket socket, InetAddress remoteAddr, int remotePort,
                            int mtu, int finSeq) throws Exception {
        int retries = 0;

        while (true) {
            TCPSegment fin = new TCPSegment();
            fin.seqNum = finSeq;
            fin.ackNum = 1;
            fin.ackFlag = true;
            fin.finFlag = true;
            fin.timestamp = System.nanoTime();

            sendSegment(socket, fin, remoteAddr, remotePort);

            try {
                while (true) {
                    byte[] buf = new byte[24 + mtu];
                    DatagramPacket dp = new DatagramPacket(buf, buf.length);
                    socket.receive(dp);

                    byte[] recv = Arrays.copyOf(dp.getData(), dp.getLength());

                    if (!checkCheckSum(recv)) {
                        checksumDiscards++;
                        continue;
                    }

                    TCPSegment seg = TCPSegment.decompose(recv);

                    logPacket("rcv", seg.synFlag, seg.ackFlag, seg.finFlag,
                            seg.dataLen, seg.seqNum, seg.ackNum, startTime);
                    packetCount++;

                    if (seg.ackFlag && seg.finFlag && seg.ackNum == finSeq + 1) {
                        TCPSegment finalAck = new TCPSegment();
                        finalAck.seqNum = finSeq + 1;
                        finalAck.ackNum = seg.seqNum + 1;
                        finalAck.ackFlag = true;
                        finalAck.timestamp = seg.timestamp;

                        sendSegment(socket, finalAck, remoteAddr, remotePort);
                        printStats();
                        return;
                    }
                }
            } catch (SocketTimeoutException e) {
                retries++;
                retransmissions++;

                if (retries > 16) {
                    System.err.println("FIN retransmit limit exceeded");
                    printStats();
                    return;
                }
            }
        }
    }

    static void runSender(DatagramSocket socket, InetAddress remoteAddr, int remotePort,
                          String filename, int mtu, int sws) throws Exception {
        long[] ewmaState = senderHandshake(socket, remoteAddr, remotePort, mtu);

        byte[] fileBytes = java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(filename));
        dataBytes = fileBytes.length;

        ArrayList<TCPSegment> packets = new ArrayList<>();

        int seq = 1; // after SYN, first data byte starts at seq 1

        for (int offset = 0; offset < fileBytes.length; offset += mtu) {
            int len = Math.min(mtu, fileBytes.length - offset);

            TCPSegment seg = new TCPSegment();
            seg.seqNum = seq;
            seg.ackNum = 1;
            seg.ackFlag = true;     // assignment says data after handshake should ACK
            seg.dataLen = len;
            seg.data = Arrays.copyOfRange(fileBytes, offset, offset + len);
            seg.timestamp = System.nanoTime();

            packets.add(seg);
            seq += len;
        }

        int base = 0;       // first unACKed packet index
        int next = 0;       // next packet index to send
        int lastAck = 1;
        int duplicateAckCount = 0;

        while (base < packets.size()) {
            // Send new packets while window has space
            while (next < packets.size() && next < base + sws) {
                TCPSegment seg = packets.get(next);
                seg.timestamp = System.nanoTime();
                sendSegment(socket, seg, remoteAddr, remotePort);
                next++;
            }

            try {
                byte[] buf = new byte[24 + mtu];
                DatagramPacket dp = new DatagramPacket(buf, buf.length);
                socket.receive(dp);

                byte[] recv = Arrays.copyOf(dp.getData(), dp.getLength());

                if (!checkCheckSum(recv)) {
                    checksumDiscards++;
                    continue;
                }

                TCPSegment ackSeg = TCPSegment.decompose(recv);

                logPacket("rcv", ackSeg.synFlag, ackSeg.ackFlag, ackSeg.finFlag,
                        ackSeg.dataLen, ackSeg.seqNum, ackSeg.ackNum, startTime);
                packetCount++;

                if (!ackSeg.ackFlag) {
                    continue;
                }

                int ackNum = ackSeg.ackNum;

                // New ACK: slide base forward past all fully ACKed packets
                if (ackNum > lastAck) {
                    lastAck = ackNum;
                    duplicateAckCount = 0;

                    while (base < packets.size()) {
                        TCPSegment first = packets.get(base);
                        int firstEnd = first.seqNum + first.dataLen;

                        if (firstEnd <= ackNum) {
                            base++;
                        } else {
                            break;
                        }
                    }
                }

                // Duplicate ACK
                else if (ackNum == lastAck) {
                    duplicateAckCount++;
                    dupAcks++;

                    // Fast retransmit: after 3 duplicate ACKs
                    if (duplicateAckCount >= 3) {
                        retransmissions++;

                        // Simple version: retransmit entire current window
                        for (int i = base; i < next; i++) {
                            TCPSegment seg = packets.get(i);
                            seg.timestamp = System.nanoTime();
                            sendSegment(socket, seg, remoteAddr, remotePort);
                        }

                        duplicateAckCount = 0;
                    }
                }

            } catch (SocketTimeoutException e) {
                // Timeout: retransmit entire current window
                retransmissions++;

                for (int i = base; i < next; i++) {
                    TCPSegment seg = packets.get(i);
                    seg.timestamp = System.nanoTime();
                    sendSegment(socket, seg, remoteAddr, remotePort);
                }
            }
        }

        senderTeardown(socket, remoteAddr, remotePort, mtu, lastAck);        
        printStats();
    }

    static void runReceiver(DatagramSocket socket, String filename,
                            int mtu, int sws) throws Exception {
        Object[] senderInfo = receiverHandshake(socket, mtu);
        InetAddress senderAddr = (InetAddress) senderInfo[0];
        int senderPort = (int) senderInfo[1];

        int expectedSeq = 1;

        try (FileOutputStream fos = new FileOutputStream(filename)) {
            while (true) {
                byte[] buf = new byte[24 + mtu];
                DatagramPacket dp = new DatagramPacket(buf, buf.length);
                socket.receive(dp);

                byte[] recv = Arrays.copyOf(dp.getData(), dp.getLength());

                if (!checkCheckSum(recv)) {
                    checksumDiscards++;
                    continue;
                }

                TCPSegment seg = TCPSegment.decompose(recv);

                logPacket("rcv", seg.synFlag, seg.ackFlag, seg.finFlag,
                        seg.dataLen, seg.seqNum, seg.ackNum, startTime);
                packetCount++;

                // Handle FIN from sender
                if (seg.finFlag) {
                    TCPSegment finAck = new TCPSegment();
                    finAck.seqNum = 1;
                    finAck.ackNum = seg.seqNum + 1;
                    finAck.ackFlag = true;
                    finAck.finFlag = true;
                    finAck.timestamp = seg.timestamp;

                    sendSegment(socket, finAck, senderAddr, senderPort);

                    // Wait for final ACK from sender
                    while (true) {
                        byte[] finalBuf = new byte[24 + mtu];
                        DatagramPacket finalDp = new DatagramPacket(finalBuf, finalBuf.length);
                        socket.receive(finalDp);

                        byte[] finalRecv = Arrays.copyOf(finalDp.getData(), finalDp.getLength());

                        if (!checkCheckSum(finalRecv)) {
                            checksumDiscards++;
                            continue;
                        }

                        TCPSegment finalAck = TCPSegment.decompose(finalRecv);

                        logPacket("rcv", finalAck.synFlag, finalAck.ackFlag, finalAck.finFlag,
                                finalAck.dataLen, finalAck.seqNum, finalAck.ackNum, startTime);
                        packetCount++;

                        if (finalAck.ackFlag && finalAck.ackNum == 2 && finalAck.seqNum == seg.seqNum + 1) {
                            printStats();
                            return;
                        }
                    }
                }

                // Ignore non-data packets here
                if (seg.dataLen <= 0) {
                    continue;
                }

                // Correct in-order packet
                if (seg.seqNum == expectedSeq) {
                    fos.write(seg.data);
                    dataBytes += seg.dataLen;
                    expectedSeq += seg.dataLen;
                }

                // Out-of-order packet
                else {
                    outOfSeq++;
                    // We drop it and ACK the last contiguous byte received
                }

                // Send cumulative ACK
                TCPSegment ack = new TCPSegment();
                ack.seqNum = 1;
                ack.ackNum = expectedSeq;
                ack.ackFlag = true;
                ack.timestamp = seg.timestamp; // echo received timestamp for RTT
                ack.dataLen = 0;

                sendSegment(socket, ack, senderAddr, senderPort);
            }
        }
    }

    public static void main(String[] args) throws Exception {
        int localPort = -1;
        String remoteIP = null;
        int remotePort = -1;
        String filename = null;
        int mtu = -1;
        int sws = -1;

        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "-p": localPort  = Integer.parseInt(args[++i]); break;
                case "-s": remoteIP   = args[++i];                   break;
                case "-a": remotePort = Integer.parseInt(args[++i]); break;
                case "-f": filename   = args[++i];                   break;
                case "-m": mtu        = Integer.parseInt(args[++i]); break;
                case "-c": sws        = Integer.parseInt(args[++i]); break;
                default:
                    System.err.println("Unknown flag: " + args[i]);
                    printUsage();
                    System.exit(1);
            }
        }

        boolean senderMode = (remoteIP != null);
        if (localPort < 0 || filename == null || mtu < 0 || sws < 0) {
            System.err.println("Missing required arguments.");
            printUsage();
            System.exit(1);
        }
        if (senderMode && remotePort < 0) {
            System.err.println("Sender mode requires -a <remotePort>.");
            printUsage();
            System.exit(1);
        }

        startTime = System.nanoTime();
        DatagramSocket socket = new DatagramSocket(localPort);

        if (senderMode) {
            runSender(socket, InetAddress.getByName(remoteIP), remotePort, filename, mtu, sws);
        } else {
            runReceiver(socket, filename, mtu, sws);
        }
    }

    static void printUsage() {
        System.err.println("Sender:   java TCPend -p <port> -s <remoteIP> -a <remotePort> -f <file> -m <mtu> -c <sws>");
        System.err.println("Receiver: java TCPend -p <port> -f <file> -m <mtu> -c <sws>");
    }

    static void printStats() {
        System.out.printf("%d %d %d %d %d %d%n",
                dataBytes, packetCount, outOfSeq,
                checksumDiscards, retransmissions, dupAcks);
    }

    static class TCPSegment {
        int seqNum, ackNum;
        long timestamp;
        int dataLen;
        boolean synFlag, finFlag, ackFlag;
        byte[] data;
        short checksum;

        byte[] compose() {
            byte[] payload = (data != null) ? data : new byte[0];
            ByteBuffer buffer = ByteBuffer.allocate(24 + payload.length);
            buffer.order(ByteOrder.BIG_ENDIAN);
            buffer.putInt(seqNum);
            buffer.putInt(ackNum);
            buffer.putLong(timestamp);
            int len = (dataLen << 3) | (synFlag ? 4 : 0) | (finFlag ? 2 : 0) | (ackFlag ? 1 : 0);
            buffer.putInt(len);
            buffer.putShort((short) 0);
            buffer.putShort((short) 0);
            buffer.put(payload);
            byte[] bytes = buffer.array();
            short cs = getChecksum(bytes);
            bytes[22] = (byte) (cs >> 8);
            bytes[23] = (byte) (cs & 0xFF);
            return bytes;
        }

        static TCPSegment decompose(byte[] bytes) {
            ByteBuffer buffer = ByteBuffer.wrap(bytes).order(ByteOrder.BIG_ENDIAN);
            TCPSegment s = new TCPSegment();
            s.seqNum = buffer.getInt();
            s.ackNum = buffer.getInt();
            s.timestamp = buffer.getLong();
            int len = buffer.getInt();
            s.dataLen = len >>> 3;
            s.synFlag = (len & 4) != 0;
            s.finFlag = (len & 2) != 0;
            s.ackFlag = (len & 1) != 0;
            buffer.getShort();
            s.checksum = buffer.getShort();
            s.data = new byte[s.dataLen];
            if (s.dataLen > 0) buffer.get(s.data);
            return s;
        }

        static short getChecksum(byte[] bytes) {
            byte firstCheckBit = bytes[22], secondCheckBit = bytes[23];
            bytes[22] = 0;
            bytes[23] = 0;
            int sum = 0;
            int len = bytes.length;
            for (int i = 0; i < len - 1; i += 2) {
                int word = ((bytes[i] & 0xFF) << 8) | (bytes[i + 1] & 0xFF);
                sum += word;
            }
            if (len % 2 == 1) {
                sum += (bytes[len - 1] & 0xFF) << 8;
            }
            while ((sum >>> 16) != 0) {
                sum = (sum & 0xFFFF) + (sum >>> 16);
            }
            bytes[22] = firstCheckBit;
            bytes[23] = secondCheckBit;
            return (short) (~sum & 0xFFFF);
        }
    }
}
