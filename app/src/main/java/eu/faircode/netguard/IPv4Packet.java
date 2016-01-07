package eu.faircode.netguard;

/*
    This file is part of NetGuard.

    NetGuard is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    NetGuard is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with NetGuard.  If not, see <http://www.gnu.org/licenses/>.

    Copyright 2015-2016 by Marcel Bokhorst (M66B)
*/

import android.util.Log;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.util.Scanner;

public class IPv4Packet {
    private static final String TAG = "NetGuard.Packet";

    private ByteBuffer packet;
    public IPv4Header IPv4;
    public UDPHeader UDP = null;
    public TCP TCP = null;

    private IPv4Packet() {
    }

    public IPv4Packet(ByteBuffer buffer) throws IOException {
        packet = buffer;

        try {
            IPv4 = new IPv4Header(buffer);
            if (IPv4.protocol == IPv4.UDP)
                UDP = new UDPHeader(buffer);
            else if (IPv4.protocol == IPv4.TCP)
                TCP = new TCP(IPv4.sourceAddress, IPv4.destinationAddress, buffer);
            else
                throw new IOException("Unsupported protocol=" + IPv4.protocol);
        } catch (IOException ex) {
            throw new IOException(ex.toString() + " " + this);
        }
    }

    public void validate() throws IOException {
        try {
            IPv4.validate();
            if (this.UDP != null)
                this.UDP.validate();
            if (this.TCP != null)
                this.TCP.validate();
        } catch (IOException ex) {
            throw new IOException(ex.toString() + " " + this);
        }
    }

    public void swapAddresses() {
        InetAddress sourceAddress = this.IPv4.sourceAddress;
        this.IPv4.sourceAddress = this.IPv4.destinationAddress;
        this.IPv4.destinationAddress = sourceAddress;
        if (this.TCP != null)
            this.TCP.swapPorts();
    }

    private void encode(ByteBuffer buffer) {
        this.IPv4.encode(buffer);
        if (this.TCP != null)
            this.TCP.encode(this.IPv4.sourceAddress, this.IPv4.destinationAddress, buffer);
        buffer.position(0);
    }

    public void send(FileOutputStream out) throws IOException {
        this.packet = ByteBuffer.allocate(32767);
        encode(this.packet);
        byte[] r = new byte[this.packet.limit()];
        this.packet.get(r);
        out.write(r);
    }

    public String toShortString() {
        StringBuilder sb = new StringBuilder();
        sb.append(this.IPv4.sourceAddress);
        if (this.TCP != null)
            sb.append(':').append(this.TCP.sourcePort);
        sb.append(" > ");
        sb.append(this.IPv4.destinationAddress);
        if (this.TCP != null)
            sb.append(':').append(this.TCP.destinationPort);
        if (this.TCP != null) {
            sb.append(" seq=").append(this.TCP.sequenceNumber);
            sb.append(" ack=").append(this.TCP.acknowledgementNumber);
            sb.append(this.TCP.getFlags());
            sb.append(this.TCP.getOptions());
            sb.append(" len=").append((this.TCP.data.length));
        }
        return sb.toString();
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder("Packet(");
        sb.append(this.IPv4);

        if (this.UDP != null)
            sb.append(", ").append(this.UDP);

        if (this.TCP != null)
            sb.append(", ").append(this.TCP);

        packet.position(0);
        byte[] buffer = new byte[packet.limit()];
        packet.get(buffer);
        sb.append(", bytes=" + Util.getHex(buffer));

        sb.append(')');
        return sb.toString();
    }

    // https://en.wikipedia.org/wiki/IPv4#Packet_structure
    public static class IPv4Header {
        public byte version;
        public byte IHL; // 32-bit words
        public byte DSCP; //  Type of service
        public byte EN;
        public int totalLength;
        public int identification;
        public byte reserved;
        public boolean DF; // Don't Fragment
        public boolean MF; // More Fragments
        public int fragmentOffset;
        public int TTL;
        public int protocol;
        public int headerChecksum;
        public InetAddress sourceAddress;
        public InetAddress destinationAddress;
        public byte[] options;

        public int calculatedHeaderChecksum;

        public static final int ICMP = 1; // Internet Control Message Protocol
        public static final int IGMP = 2; // Internet Group Management Protocol
        public static final int TCP = 6; // Transmission Control Protocol
        public static final int UDP = 17; // User Packet Protocol
        public static final int ENCAP = 41; // IPv6 encapsulation
        public static final int OSPF = 89; // Open Shortest Path First
        public static final int SCTP = 132; // Stream Control Transmission Protocol

        private IPv4Header(int protocol, InetAddress sourceAddress, InetAddress destinationAddress) {
            this.version = 4;
            this.IHL = 5;
            this.DSCP = 0;
            this.EN = 0;
            this.totalLength = 20;
            this.identification = 0;
            this.reserved = 0;
            this.DF = false;
            this.MF = false;
            this.fragmentOffset = 0;
            this.TTL = 64;
            this.protocol = protocol;
            this.sourceAddress = sourceAddress;
            this.destinationAddress = destinationAddress;
            this.options = new byte[0];
        }

        public IPv4Header(ByteBuffer buffer) throws IOException {
            int pos = buffer.position();

            int b = buffer.get();
            this.version = (byte) (b >> 4);
            this.IHL = (byte) (b & 0xF);

            if (this.version != 4)
                throw new IOException("IP: Invalid version=" + this.version);

            b = buffer.get();
            this.DSCP = (byte) (b >> 4);
            this.EN = (byte) (b & 0xF);

            this.totalLength = buffer.getShort() & 0xFFFF;
            this.identification = buffer.getShort() & 0xFFFF;

            b = buffer.getShort();
            byte flags = (byte) (b >> 13);
            this.reserved = (byte) (flags & 1);
            this.DF = (flags & 2) != 0;
            this.MF = (flags & 4) != 0;
            this.fragmentOffset = b & 0x1FFF; // eight-byte blocks (64 bits)

            this.TTL = buffer.get() & 0xFF;
            this.protocol = buffer.get() & 0xFF;
            this.headerChecksum = buffer.getShort() & 0xFFFF;

            byte[] addressBytes = new byte[4];
            buffer.get(addressBytes, 0, 4);
            this.sourceAddress = InetAddress.getByAddress(addressBytes);

            buffer.get(addressBytes, 0, 4);
            this.destinationAddress = InetAddress.getByAddress(addressBytes);

            int optionsLength = this.IHL * 4 - 20;
            this.options = new byte[optionsLength];
            if (optionsLength > 0)
                buffer.get(this.options);

            buffer.putShort(pos + 10, (short) 0);
            this.calculatedHeaderChecksum = Util.getChecksum(buffer, pos, buffer.position() - pos);
        }

        private int getFlags() {
            return this.reserved | (this.DF ? 2 : 0) | (this.MF ? 4 : 0);
        }

        public void encode(ByteBuffer buffer) {
            int pos = buffer.position();

            buffer.put((byte) (this.version << 4 | this.IHL));
            buffer.put((byte) (this.DSCP << 4 | this.EN));
            buffer.putShort((short) this.totalLength);
            buffer.putShort((short) this.identification);
            buffer.putShort((short) (this.getFlags() << 13 | this.fragmentOffset));
            buffer.put((byte) this.TTL);
            buffer.put((byte) this.protocol);
            buffer.putShort((short) 0); // checksum
            buffer.put(this.sourceAddress.getAddress());
            buffer.put(this.destinationAddress.getAddress());
            buffer.put(this.options);

            int checksum = Util.getChecksum(buffer, pos, buffer.position() - pos);
            buffer.putShort(pos + 10, (short) checksum);
        }

        public void validate() throws IOException {
            if (this.IHL < 5)
                throw new IOException("IP: Invalid IHL");
            if (this.totalLength < 20)
                throw new IOException("IP: Invalid total length");
            if (this.reserved != 0)
                throw new IOException("IP: Reserved not zero");
            if (this.headerChecksum != this.calculatedHeaderChecksum)
                throw new IOException(("IP: Invalid header checksum"));
        }

        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder("IPv4Header(");
            sb.append("version=").append(this.version);
            sb.append(", IHL=").append(this.IHL);
            sb.append(", DSCP=").append(this.DSCP);
            sb.append(", EN=").append(this.EN);
            sb.append(", totalLength=").append(this.totalLength);
            sb.append(", reserved=").append(this.reserved);
            sb.append(", DF=").append(this.DF);
            sb.append(", MF=").append(this.MF);
            sb.append(", fragmentOffset=").append(this.fragmentOffset);
            sb.append(", TTL=").append(this.TTL);
            sb.append(", protocol=").append(this.protocol);
            sb.append(", headerChecksum=").append(this.headerChecksum);
            sb.append(", sourceAddress=").append(this.sourceAddress.getHostAddress());
            sb.append(", destinationAddress=").append(this.destinationAddress.getHostAddress());
            sb.append(", options=" + Util.getHex(this.options));
            sb.append(", calculatedHeaderChecksum=").append(this.calculatedHeaderChecksum);
            sb.append(')');
            return sb.toString();
        }
    }

    // https://en.wikipedia.org/wiki/User_Datagram_Protocol
    public class UDPHeader {
        public int sourcePort;
        public int destinationPort;
        public int length;
        public int checksum;

        public UDPHeader(ByteBuffer buffer) {
            int pos = buffer.position();

            this.sourcePort = buffer.getShort() & 0xFFFF;
            this.destinationPort = buffer.getShort() & 0xFFFF;
            this.length = buffer.getShort() & 0xFFFF;
            this.checksum = buffer.getShort() & 0xFFFF;
        }

        public void validate() throws IOException {
        }
    }

    // https://en.wikipedia.org/wiki/Transmission_Control_Protocol
    public static class TCP {
        public int sourcePort;
        public int destinationPort;
        public long sequenceNumber;
        public long acknowledgementNumber;
        public byte dataOffset; // 32-bit words
        public byte reserved;
        public boolean NS;
        public boolean CWR;
        public boolean ECE;
        public boolean URG;
        public boolean ACK;
        public boolean PSH;
        public boolean RST;
        public boolean SYN;
        public boolean FIN;
        public int windowSize;
        public int checksum;
        public int urgentPointer;
        public byte[] options;
        public byte[] data;

        public int calculatedChecksum;

        private TCP(int sourcePort, int destinationPort) {
            this.sourcePort = sourcePort;
            this.destinationPort = destinationPort;
            this.dataOffset = 5;
            this.reserved = 0;
            this.windowSize = 65535;
            this.urgentPointer = 0;
            this.options = new byte[0];
        }

        public TCP(InetAddress source, InetAddress destination, ByteBuffer buffer) {
            int pos = buffer.position();

            this.sourcePort = buffer.getShort() & 0xFFFF;
            this.destinationPort = buffer.getShort() & 0xFFFF;
            this.sequenceNumber = buffer.getInt() & 0xFFFFFFFFL;
            this.acknowledgementNumber = buffer.getInt() & 0xFFFFFFFFL;

            int flags = buffer.getShort() & 0xFFFF;
            this.dataOffset = (byte) (flags >> 12);
            this.reserved = (byte) ((flags >> 9) & 0x7);
            this.NS = (flags & 0x100) != 0;
            this.CWR = (flags & 0x80) != 0;
            this.ECE = (flags & 0x40) != 0;
            this.URG = (flags & 0x20) != 0;
            this.ACK = (flags & 0x10) != 0;
            this.PSH = (flags & 0x8) != 0;
            this.RST = (flags & 0x4) != 0;
            this.SYN = (flags & 0x2) != 0;
            this.FIN = (flags & 0x1) != 0;

            this.windowSize = buffer.getShort() & 0xFFFF;
            this.checksum = buffer.getShort() & 0xFFFF;
            this.urgentPointer = buffer.getShort() & 0xFFFF;

            int optionsLength = this.dataOffset * 4 - 20;
            this.options = new byte[optionsLength];
            if (optionsLength > 0)
                buffer.get(this.options);

            this.data = new byte[buffer.limit() - buffer.position()];
            buffer.get(this.data);

            buffer.putShort(pos + 16, (short) 0);

            // pseudo header
            ByteBuffer cc = ByteBuffer.allocate(12 + buffer.position() - pos);
            cc.put(source.getAddress());
            cc.put(destination.getAddress());
            cc.put((byte) 0);
            cc.put((byte) 6);
            cc.putShort((short) (buffer.position() - pos));
            // TODO: combine two checksums
            for (int i = pos; i < buffer.position(); i++)
                cc.put(buffer.get(i));

            this.calculatedChecksum = Util.getChecksum(cc, 0, cc.limit());
        }

        private int getFlagValue() {
            return (this.NS ? 0x100 : 0) |
                    (this.CWR ? 0x80 : 0) |
                    (this.ECE ? 0x40 : 0) |
                    (this.URG ? 0x20 : 0) |
                    (this.ACK ? 0x10 : 0) |
                    (this.PSH ? 0x8 : 0) |
                    (this.RST ? 0x4 : 0) |
                    (this.SYN ? 0x2 : 0) |
                    (this.FIN ? 0x1 : 0);
        }

        public void clearFlags() {
            this.NS = false;
            this.CWR = false;
            this.ECE = false;
            this.URG = false;
            this.ACK = false;
            this.PSH = false;
            this.RST = false;
            this.SYN = false;
            this.FIN = false;
        }

        public void encode(InetAddress source, InetAddress destination, ByteBuffer buffer) {
            int pos = buffer.position();

            buffer.putShort((short) this.sourcePort);
            buffer.putShort((short) this.destinationPort);
            buffer.putInt((int) this.sequenceNumber);
            buffer.putInt((int) this.acknowledgementNumber);
            buffer.putShort((short) (this.dataOffset << 12 | this.reserved << 9 | this.getFlagValue()));
            buffer.putShort((short) this.windowSize);
            buffer.putShort((short) 0); // checksum
            buffer.putShort((short) this.urgentPointer);
            buffer.put(this.options);
            buffer.put(this.data);

            ByteBuffer cc = ByteBuffer.allocate(12 + buffer.position() - pos);
            cc.put(source.getAddress());
            cc.put(destination.getAddress());
            cc.put((byte) 0); // reserved
            cc.put((byte) 6); // protocol=TCP
            cc.putShort((short) (buffer.position() - pos));
            // TODO: combine two checksums
            for (int i = pos; i < buffer.position(); i++)
                cc.put(buffer.get(i));
            int checksum = Util.getChecksum(cc, 0, cc.limit());

            buffer.putShort(pos + 16, (short) checksum);
        }

        public void validate() throws IOException {
            if (this.dataOffset < 5 || this.dataOffset > 15)
                throw new IOException("TCP: Invalid data offset");
            if (this.reserved != 0)
                throw new IOException("TCP: Reserved not zero");
            if (this.checksum != this.calculatedChecksum)
                throw new IOException(("TCP: Invalid checksum"));
        }

        public String getFlags() {
            StringBuilder sb = new StringBuilder();
            if (this.FIN)
                sb.append(" FIN");
            if (this.SYN)
                sb.append(" SYN");
            if (this.RST)
                sb.append(" RST");
            if (this.PSH)
                sb.append(" PSH");
            if (this.ACK)
                sb.append(" ACK");
            if (this.URG)
                sb.append(" URG");
            if (this.ECE)
                sb.append(" ECE");
            if (this.CWR)
                sb.append(" CWR");
            if (this.NS)
                sb.append(" NS");
            return sb.toString();
        }

        public String getOptions() {
            StringBuilder sb = new StringBuilder();
            int i = 0;
            while (i < this.options.length) {
                byte okind = this.options[i++];
                sb.append(' ').append(okind).append('=');
                if (okind > 1) {
                    int olen = this.options[i++] - 2;
                    while (olen > 0) {
                        olen--;
                        sb.append(String.format("%02X", this.options[i++]));
                    }
                }
            }
            return sb.toString();
        }

        public void swapPorts() {
            int sourcePort = this.sourcePort;
            this.sourcePort = this.destinationPort;
            this.destinationPort = sourcePort;
        }

        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder("TCP(");
            sb.append("sourcePort=").append(this.sourcePort);
            sb.append(", destinationPort=").append(this.destinationPort);
            sb.append(", sequenceNumber=").append(this.sequenceNumber);
            sb.append(", acknowledgementNumber=").append(this.acknowledgementNumber);
            sb.append(", dataOffset=").append(this.dataOffset);
            sb.append(", reserved=").append(this.reserved);
            sb.append(", flags=").append(getFlags());
            sb.append(", windowSize=").append(this.windowSize);
            sb.append(", checksum=").append(this.checksum);
            sb.append(", urgentPointer=").append(this.urgentPointer);
            sb.append(", option=").append(getOptions());
            sb.append(", data=").append(Util.getHex(this.data));
            sb.append(", calculatedHeaderChecksum=").append(this.calculatedChecksum);
            sb.append(')');
            return sb.toString();
        }
    }

    public int getUid() {
        if (this.TCP == null && this.UDP == null)
            return -1;

        StringBuilder addr = new StringBuilder();
        byte[] b = this.IPv4.sourceAddress.getAddress();
        for (int i = b.length - 1; i >= 0; i--)
            addr.append(String.format("%02X", b[i]));

        String port = String.format("%04X", this.TCP == null ? this.UDP.sourcePort : this.TCP.sourcePort);

        int uid = scanUid("0000000000000000FFFF0000" + addr.toString() + ":" + port, this.TCP == null ? "/proc/net/udp6" : "/proc/net/tcp6");
        if (uid < 0)
            uid = scanUid(addr.toString() + ":" + port, this.TCP == null ? "/proc/net/udp" : "/proc/net/tcp");
        if (uid < 0 && this.UDP != null)
            uid = scanUid("00000000:" + port, "/proc/net/udp");

        // IPv6 5014002A010C13400000000084000000 = 2a00:1450:4013:c01::84

        return uid;
    }

    private static int scanUid(String addr, String name) {
        File file = new File(name);
        Scanner scanner = null;
        try {
            scanner = new Scanner(file);
            while (scanner.hasNextLine()) {
                String line = scanner.nextLine().trim();
                if (line.startsWith("sl"))
                    continue;

                String[] field = line.split("\\s+");
                if (addr.equals(field[1]))
                    return Integer.parseInt(field[7]);
            }
        } catch (FileNotFoundException ex) {
            Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
        } finally {
            if (scanner != null)
                scanner.close();
        }

        return -1;
    }

    public static class Util {
        private static final char[] hex = "0123456789ABCDEF".toCharArray();

        public static String getHex(byte[] buffer) {
            StringBuffer sb = new StringBuffer(buffer.length * 3);
            for (int i = 0; i < buffer.length; i++) {
                int v = buffer[i] & 0xFF;
                if (i != 0)
                    sb.append(' ');
                sb.append(hex[v >>> 4]);
                sb.append(hex[v & 0x0F]);
            }
            return sb.toString();
        }

        public static int getChecksum(ByteBuffer buffer, int position, int length) {
            int i = 0;
            long sum = 0;
            long data;
            while (length > 1) {
                data = (((buffer.get(position + i) << 8) & 0xFF00) | (buffer.get(position + i + 1) & 0xFF));
                sum += data;
                if ((sum & 0xFFFF0000) > 0) {
                    sum = sum & 0xFFFF;
                    sum += 1;
                }
                i += 2;
                length -= 2;
            }

            if (length > 0) {
                sum += (buffer.get(position + i) << 8 & 0xFF00);
                if ((sum & 0xFFFF0000) > 0) {
                    sum = sum & 0xFFFF;
                    sum += 1;
                }
            }

            sum = ~sum;
            sum = sum & 0xFFFF;
            return (int) sum;
        }
    }
}
