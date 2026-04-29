import java.net.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

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

    // Returns true if the packet's stored checksum matches
    static boolean checkCheckSum(byte[] bytes) {
        short stored = (short) (((bytes[22] & 0xFF) << 8) | (bytes[23] & 0xFF));
        return stored == TCPSegment.getChecksum(bytes);
    }

    static void sendSegment(DatagramSocket socket, TCPSegment seg, InetAddress addr, int port) throws Exception {
        byte[] bytes = seg.compose();
        socket.send(new DatagramPacket(bytes, bytes.length, addr, port));
        logPacket("snd", seg.synFlag, seg.ackFlag, seg.finFlag,
                seg.dataLen, seg.seqNum, seg.ackNum, startTime);
        packetCount++;
    }

    static long[] senderHandshake(DatagramSocket socket, InetAddress remoteAddr, int remotePort, int mtu) throws Exception {
        long timeoutNs = 5_000_000_000L;
        socket.setSoTimeout(5000);

        int synRetries = 0;
        long estimatedRTT = 0, estimatedDeviation = 0;

        outer:
        while (true) {
            // Build and send SYN
            TCPSegment syn = new TCPSegment();
            syn.seqNum = 0;
            syn.synFlag = true;
            syn.timestamp = System.nanoTime();
            sendSegment(socket, syn, remoteAddr, remotePort);

            // Wait for SYN+ACK
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
                    packetCount++;

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

        // Wait for valid SYN
        while (true) {
            byte[] buf = new byte[24 + mtu];
            DatagramPacket dp = new DatagramPacket(buf, buf.length);
            socket.receive(dp);
            byte[] recv = Arrays.copyOf(dp.getData(), dp.getLength());

            if (!checkCheckSum(recv)) { checksumDiscards++; continue; }

            TCPSegment seg = TCPSegment.decompose(recv);
            if (seg.synFlag && seg.seqNum == 0) {
                logPacket("rcv", true, seg.ackFlag, false,
                        0, 0, seg.ackNum, startTime);
                packetCount++;
                senderAddr = dp.getAddress();
                senderPort = dp.getPort();

                // Build SYN+ACK, echoing the SYN's timestamp
                TCPSegment synAck = new TCPSegment();
                synAck.seqNum = 0;
                synAck.ackNum = 1;
                synAck.synFlag = true;
                synAck.ackFlag = true;
                synAck.timestamp = seg.timestamp;
                synAckBytes = synAck.compose();
                socket.send(new DatagramPacket(synAckBytes, synAckBytes.length,
                        senderAddr, senderPort));
                logPacket("snd", true, true, false, 0, 0, 1, startTime);
                packetCount++;
                break;
            }
        }

        // Wait for final ACK; re-send SYN+ACK on duplicate SYN
        while (true) {
            byte[] buf = new byte[24 + mtu];
            DatagramPacket dp = new DatagramPacket(buf, buf.length);
            socket.receive(dp);
            byte[] recv = Arrays.copyOf(dp.getData(), dp.getLength());

            if (!checkCheckSum(recv)) { checksumDiscards++; continue; }

            TCPSegment seg = TCPSegment.decompose(recv);

            if (seg.synFlag && seg.seqNum == 0) {
                logPacket("rcv", true, seg.ackFlag, false, 0, 0, seg.ackNum, startTime);
                socket.send(new DatagramPacket(synAckBytes, synAckBytes.length,
                        senderAddr, senderPort));
                logPacket("snd", true, true, false, 0, 0, 1, startTime);
                continue;
            }

            if (seg.ackFlag && seg.ackNum == 1) {
                logPacket("rcv", false, true, false,
                        seg.dataLen, seg.seqNum, seg.ackNum, startTime);
                packetCount++;
                break;
            }
        }

        return new Object[]{senderAddr, senderPort};
    }

    static void runSender(DatagramSocket socket, InetAddress remoteAddr, int remotePort,
                          String filename, int mtu, int sws) throws Exception {
        long[] ewmaState = senderHandshake(socket, remoteAddr, remotePort, mtu);
        // ewmaState = {estimatedRTT, estimatedDeviation, timeoutNs}
        throw new UnsupportedOperationException("data transfer not yet implemented");
    }

    static void runReceiver(DatagramSocket socket, String filename,
                            int mtu, int sws) throws Exception {
        Object[] senderInfo = receiverHandshake(socket, mtu);
        InetAddress senderAddr = (InetAddress) senderInfo[0];
        int senderPort = (int) senderInfo[1];
        int expectedSeq = 1;

        throw new UnsupportedOperationException("data path not yet implemented");
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
            buffer.putShort((short) 0); // bytes 20-21: padding
            buffer.putShort((short) 0); // bytes 22-23: checksum placeholder
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
            buffer.getShort(); // skip padding bytes 20-21
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
