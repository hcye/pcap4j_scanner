package com.hcye.myScanner.packetBuilder;
import java.net.Inet4Address;
import java.net.UnknownHostException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV4Rfc1349Tos;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.UdpPacket;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.IpVersion;
import org.pcap4j.packet.namednumber.UdpPort;
import org.pcap4j.util.MacAddress;
import com.hcye.myScanner.Pcap4JTools;
import com.hcye.myScanner.inter.PacketBuilder;
import org.pcap4j.packet.UnknownPacket.Builder;

public class BuildUdpPacket implements PacketBuilder {
  private final int srcPort;
  private final int dstPort;
  private final short length;
  private final short checksum;
  private final UdpPacket packet;
  private final PcapNetworkInterface nif;

  public BuildUdpPacket(PcapNetworkInterface nif,int dstPort,int srcPort) throws Exception {
	this.nif=nif;
    this.srcPort = srcPort;
    this.dstPort = dstPort;
    this.length = (short) 12;
    this.checksum = (short) ((short) 20000 + Math.random() * 10000);

    Builder unknownb = new Builder();
    unknownb.rawData(new byte[] {(byte) 0, (byte) 1, (byte) 2, (byte) 3});
    
    UdpPacket.Builder b = new UdpPacket.Builder();
    b.dstPort(UdpPort.getInstance((short) dstPort))
        .srcPort(UdpPort.getInstance((short) srcPort))
        .length(length)
        .checksum(checksum)
        .correctChecksumAtBuild(false)
        .correctLengthAtBuild(false);
    b.payloadBuilder(unknownb);
    this.packet = b.build();
  }



@Override
public Packet getWholePacket(String dstIp, String dstMac) throws UnknownHostException {
	// TODO Auto-generated method stub
    IpV4Packet.Builder Ipv4b = new IpV4Packet.Builder();
    String srcIp=Pcap4JTools.getIpByNif(nif);
    Inet4Address srcAddr = (Inet4Address) Inet4Address.getByName(srcIp);
    Inet4Address dstAddr = (Inet4Address) Inet4Address.getByName(dstIp);
    String srcMacAddr=Pcap4JTools.getMacByNif(nif);
    Ipv4b.version(IpVersion.IPV4)
    		.tos(IpV4Rfc1349Tos.newInstance((byte) 0))
    		.identification((short) ((short) 20000 + Math.random() * 10000))
    		.ttl((byte) 100)
    		.protocol(IpNumber.UDP)
    		.srcAddr(srcAddr)   
    		.dstAddr(dstAddr)
    		.payloadBuilder(
            packet
                    .getBuilder()
                    .correctChecksumAtBuild(true)
                    .correctLengthAtBuild(true))
                    .correctChecksumAtBuild(true)
                    .correctLengthAtBuild(true)
                    .paddingAtBuild(true);
    EthernetPacket.Builder eb = new EthernetPacket.Builder();
    eb.dstAddr(MacAddress.getByName(dstMac))
        .srcAddr(MacAddress.getByName(srcMacAddr)) 
        .type(EtherType.IPV4)
        .payloadBuilder(Ipv4b)
        .paddingAtBuild(true);
    	
    eb.get(UdpPacket.Builder.class).dstAddr(dstAddr).srcAddr(srcAddr);
    return eb.build();
}



@Override
public Packet getPacket() {
	// TODO Auto-generated method stub
	return packet;
}

}
