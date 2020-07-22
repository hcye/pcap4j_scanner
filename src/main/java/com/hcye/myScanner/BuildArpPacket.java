package com.hcye.myScanner;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.ArpHardwareType;
import org.pcap4j.packet.namednumber.ArpOperation;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.util.ByteArrays;
import org.pcap4j.util.MacAddress;

import java.net.InetAddress;
import java.net.UnknownHostException;

public class BuildArpPacket implements PacketBuilder {
    private final String srcIpAddress;
    private final String srcMac;
    public BuildArpPacket(PcapNetworkInterface nif){
        this.srcIpAddress=Pcap4JTools.getIpByNif(nif);
        this.srcMac = Pcap4JTools.getMacByNif(nif);
    }
    @Override
    public Packet getPacket() {
        return null;
    }

    @Override
    public Packet getWholePacket(String dstIp, String dstMac) {
        ArpPacket.Builder arpBuilder = new ArpPacket.Builder();
        try {
            arpBuilder
                    .hardwareType(ArpHardwareType.ETHERNET)
                    .protocolType(EtherType.IPV4)
                    .hardwareAddrLength((byte) MacAddress.SIZE_IN_BYTES)
                    .protocolAddrLength((byte) ByteArrays.INET4_ADDRESS_SIZE_IN_BYTES)
                    .operation(ArpOperation.REQUEST)
                    .srcHardwareAddr(MacAddress.getByName(srcMac))
                    .srcProtocolAddr(InetAddress.getByName(srcIpAddress))
                    .dstHardwareAddr(MacAddress.ETHER_BROADCAST_ADDRESS)
                    .dstProtocolAddr(InetAddress.getByName(dstIp));
        } catch (UnknownHostException e) {
            throw new IllegalArgumentException(e);
        }

        EthernetPacket.Builder etherBuilder = new EthernetPacket.Builder();
        etherBuilder
                .dstAddr(MacAddress.ETHER_BROADCAST_ADDRESS)
                .srcAddr(MacAddress.getByName(srcMac))
                .type(EtherType.ARP)
                .payloadBuilder(arpBuilder)
                .paddingAtBuild(true);


        return   etherBuilder.build();
    }


}
