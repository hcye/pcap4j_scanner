package com.hcye.myScanner;


import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;

import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IcmpV4CommonPacket;
import org.pcap4j.packet.IcmpV4EchoPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV4Rfc1349Tos;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.SimpleBuilder;
import org.pcap4j.packet.UnknownPacket.Builder;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.packet.namednumber.IcmpV4Code;
import org.pcap4j.packet.namednumber.IcmpV4Type;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.IpVersion;
import org.pcap4j.util.MacAddress;

import com.hcye.myScanner.inter.PacketBuilder;


public class BuildIcmpPacket implements PacketBuilder {


    private final IcmpV4EchoPacket packet;
    private final short identifier;
    private final short sequenceNumber;
    private final String srcIp;
    private final String srcMac;

    public BuildIcmpPacket(PcapNetworkInterface nif) {
        this.srcIp = Pcap4JTools.getIpByNif(nif);
        this.srcMac = Pcap4JTools.getMacByNif(nif);
        this.identifier = (short) ((short) Math.random() * 30000);
        this.sequenceNumber = (short) 0;
        Builder unknownb = new Builder();
        unknownb.rawData(new byte[]{(byte) 0});
        IcmpV4EchoPacket.Builder b = new IcmpV4EchoPacket.Builder();
        b.identifier(identifier).sequenceNumber(sequenceNumber).payloadBuilder(unknownb);
        this.packet = b.build();
    }

    @Override
    public Packet getPacket() {
        return packet;
    }

    @Override
    public Packet getWholePacket(String dstIp, String dstMac) throws UnknownHostException {
        IcmpV4CommonPacket.Builder icmpV4b = new IcmpV4CommonPacket.Builder();
        icmpV4b
                .type(IcmpV4Type.ECHO)
                .code(IcmpV4Code.NO_CODE)
                .payloadBuilder(new SimpleBuilder(packet))
                .correctChecksumAtBuild(true);
        IpV4Packet.Builder ipv4b = new IpV4Packet.Builder();
        ipv4b
                .version(IpVersion.IPV4)
                .tos(IpV4Rfc1349Tos.newInstance((byte) 0))
                .identification((short) ((short) 20000 + Math.random() * 10000))
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


