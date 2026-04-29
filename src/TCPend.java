import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class TCPend {
    static class TCPSegment {
        int seqNum, ackNum;
        long timestamp;
        int dataLen;
        boolean synFlag, finFlag, ackFlag;
        byte[] data;
        short checksum;

        byte[] serialize() {
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
        static TCPSegment deserialize(byte[] bytes) {
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
