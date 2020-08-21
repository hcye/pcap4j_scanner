package com.hcye.myScanner.packetBuilder;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;

import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IcmpV4CommonPacket.Builder;
import org.pcap4j.packet.IcmpV4TimestampPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV4Rfc1349Tos;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.SimpleBuilder;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.packet.namednumber.IcmpV4Code;
import org.pcap4j.packet.namednumber.IcmpV4Type;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.IpVersion;
import org.pcap4j.util.MacAddress;

import com.hcye.myScanner.Pcap4JTools;
import com.hcye.myScanner.inter.PacketBuilder;

public class BuildTimeStampPacket implements PacketBuilder {
    private final IcmpV4TimestampPacket packet;
    private final short identifier;
    private final short sequenceNumber;
    private final int originateTimestamp;
    private final int receiveTimestamp;
    private final int transmitTimestamp;
    private final String srcIp;
    private final String srcMac;
    public BuildTimeStampPacket(PcapNetworkInterface nif) {
    	this.srcIp = Pcap4JTools.getIpByNif(nif);
        this.srcMac = Pcap4JTools.getMacByNif(nif);
        this.identifier = (short) ((short) Math.random()*10000+1000);
        this.sequenceNumber = (short) 0;
        this.originateTimestamp = 0;
        this.receiveTimestamp = 0;
        this.transmitTimestamp = 0;

        IcmpV4TimestampPacket.Builder b = new IcmpV4TimestampPacket.Builder();
        b.identifier(identifier)
                .sequenceNumber(sequenceNumber)
                .originateTimestamp(originateTimestamp)
                .receiveTimestamp(receiveTimestamp)
                .transmitTimestamp(transmitTimestamp);
        this.packet = b.build();
    }

    @Override
    public Packet getPacket() {
        return packet;
    }

    @Override
    public Packet getWholePacket(String dstIp, String dstMac) throws UnknownHostException {
        Builder icmpV4b = new Builder();
        icmpV4b
                .type(IcmpV4Type.TIMESTAMP)
                .code(IcmpV4Code.NO_CODE)
                .payloadBuilder(new SimpleBuilder(packet))
                .correctChecksumAtBuild(true);

        IpV4Packet.Builder ipv4b = new IpV4Packet.Builder();
        ipv4b
                .version(IpVersion.IPV4)
                .tos(IpV4Rfc1349Tos.newInstance((byte) 0))
                .identification((short) 100)
                .ttl((byte) 100)
                .protocol(IpNumber.ICMPV4)
                .srcAddr(
                        (Inet4Address)
                                InetAddress.getByName(srcIp))
                .dstAddr(
                        (Inet4Address)
                                InetAddress.getByName(dstIp))
                .payloadBuilder(icmpV4b)
                .correctChecksumAtBuild(true)
                .correctLengthAtBuild(true);

        EthernetPacket.Builder eb = new EthernetPacket.Builder();
        eb.dstAddr(MacAddress.getByName(dstMac))
                .srcAddr(MacAddress.getByName(srcMac))
                .type(EtherType.IPV4)
                .payloadBuilder(ipv4b)
                .paddingAtBuild(true);
        return eb.build();
    }
}
