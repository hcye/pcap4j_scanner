package com.hcye.myScanner;



import java.net.Inet4Address;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;

import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.packet.*;
import org.pcap4j.packet.TcpMaximumSegmentSizeOption.Builder;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.IpVersion;
import org.pcap4j.packet.namednumber.TcpPort;
import org.pcap4j.util.MacAddress;


public class BuildSynpacket implements PacketBuilder {
    private final TcpPort srcPort;
    private final TcpPort dstPort;
    private final int sequenceNumber;
    private final byte dataOffset;
    private final boolean syn;
    private final short window;
    private final short checksum;
    private final List<TcpPacket.TcpOption> options;
    private final TcpPacket packet;
    private final String srcMac;
    private final String srcIp;

    public BuildSynpacket( PcapNetworkInterface nif)  {
        this.srcIp = Pcap4JTools.getIpByNif(nif);
        this.srcMac = Pcap4JTools.getMacByNif(nif);
        this.srcPort = TcpPort.getInstance((short) ((short) 30000 + Math.random() * 20000));
        this.dstPort = TcpPort.getInstance((short) 443);
        this.sequenceNumber = (short) ((short) 20000 + Math.random() * 20000);
        this.dataOffset = 0;
        this.syn = true;
        this.window = (short) 1024;
        this.checksum = (short) ((short) 20000 + Math.random() * 10000);
        this.options = new ArrayList<TcpPacket.TcpOption>();
        options.add(new Builder().maxSegSize((short) 1460).correctLengthAtBuild(true).build());
        TcpPacket.Builder b = new TcpPacket.Builder();
        b.dstPort(dstPort)
                .srcPort(srcPort)
                .sequenceNumber(sequenceNumber)
                .dataOffset(dataOffset)
                .syn(syn)
                .window(window)
                .checksum(checksum)
                .options(options)
                .correctChecksumAtBuild(false)
                .correctLengthAtBuild(false)
                .paddingAtBuild(true);
        this.packet = b.build();
    }

    @Override
    public Packet getPacket() {
        return packet;
    }

    @Override
    public Packet getWholePacket(String dstIp, String dstMac) throws UnknownHostException {
        Inet4Address srcAddr = (Inet4Address) Inet4Address.getByName(srcIp);
        Inet4Address dstAddr = (Inet4Address) Inet4Address.getByName(dstIp);
        IpV4Packet.Builder IpV4b = new IpV4Packet.Builder();
        IpV4b.version(IpVersion.IPV4)
                .tos(IpV4Rfc1349Tos.newInstance((byte) 0))
                .identification((short) ((short) 20000 + Math.random() * 10000))
                .ttl((byte) 100)
                .protocol(IpNumber.TCP)
                .srcAddr(srcAddr)
                .dstAddr(dstAddr)
                .payloadBuilder(
                        packet
                                .getBuilder()
                                .correctChecksumAtBuild(true)
                                .correctLengthAtBuild(true)
                                .paddingAtBuild(true))
                .correctChecksumAtBuild(true)
                .correctLengthAtBuild(true)
                .paddingAtBuild(true);

        EthernetPacket.Builder eb = new EthernetPacket.Builder();
        eb.dstAddr(MacAddress.getByName(dstMac))
                .srcAddr(MacAddress.getByName(srcMac))
                .type(EtherType.IPV4)
                .payloadBuilder(IpV4b)
                .paddingAtBuild(true);
        eb.get(TcpPacket.Builder.class).dstAddr(dstAddr).srcAddr(srcAddr);
        return eb.build();
    }

}
