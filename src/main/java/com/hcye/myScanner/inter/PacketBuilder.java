package com.hcye.myScanner.inter;
import org.pcap4j.packet.Packet;
import java.net.UnknownHostException;

public interface PacketBuilder {
     Packet getPacket();
     Packet getWholePacket(String dstIp, String dstMac) throws UnknownHostException;
}
