package com.hcye.myScanner;

import org.pcap4j.core.*;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.IcmpV4EchoReplyPacket;
import org.pcap4j.packet.IcmpV4TimestampReplyPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.namednumber.ArpOperation;
import org.pcap4j.packet.namednumber.TcpPort;

import com.hcye.myScanner.inter.PacketBuilder;

import java.util.*;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

public class MyPacketListener {
	private int counter=0;
    public Set<String> lisener(String dstip, PcapNetworkInterface nif,List<PacketBuilder> builder) throws PcapNativeException{
    	Pcap4JTools tools = new Pcap4JTools(dstip);
        String srcip = Pcap4JTools.getIpByNif(nif);
        Set<String> set = new HashSet<>();
        PcapHandle.Builder handleBuilder =
    	        new PcapHandle.Builder(nif.getName())
    	            .snaplen(65536)
    	            .promiscuousMode(PromiscuousMode.PROMISCUOUS)
    	            .timeoutMillis(10)
    	            .bufferSize(1024*1024*10);
    	    PcapHandle sendHandler=handleBuilder.build();
      
        String ipHead =tools.getIphead();
        /*
         * 	获得需要扫描的ip总数
         * 
         * */
        int scanIpCount =( tools.getEnd() - tools.getStart())*builder.size();
        ExecutorService pool=Executors.newSingleThreadExecutor();
        timer t=new timer(scanIpCount);
        Future<Boolean> f=pool.submit(t);
        try {
			while(!f.isDone()) {
				Packet packet=sendHandler.getNextPacket();
				if(packet==null) {
					continue;
				}
				for(PacketBuilder b:builder) {
			 	if(b.getClass().getSimpleName().equals("BuildArpPacket")) {
					if(packet.contains(ArpPacket.class)) {
						ArpPacket arp=packet.get(ArpPacket.class);
						if(arp.getHeader().getOperation()==ArpOperation.REPLY) {
							/**
							 * 	转换成arp包，过滤reply包
							 *  Convert to ipv4 packet to judge 
							 * 
							 * */
							  counter++;
							  for (int i = tools.getStart(); i <=  tools.getEnd(); i++) {
			                      if (arp.getHeader().getDstProtocolAddr().getHostAddress().equals(srcip) && arp.getHeader().getSrcProtocolAddr().getHostAddress().equals(ipHead + i))
			                          set.add(ipHead + i);
			                  }
						}
			    	}
					
				}else if (b.getClass().getSimpleName().equals("BuildIcmpPacket")||b.getClass().getSimpleName().equals("BuildTimeStampPacket")) {
					if(packet.contains(IcmpV4EchoReplyPacket.class)||packet.contains(IcmpV4TimestampReplyPacket.class)) {
						IpV4Packet icmpreply=packet.get(IpV4Packet.class);
						/**
						 *	转换成IPv4包进行判断
						 *	Convert to ipv4 packet to judge 
						 * */
						 counter++;
						 for (int i =tools.getStart(); i <= tools.getEnd(); i++) {
			                 if (icmpreply.getHeader().getSrcAddr().getHostAddress().equals(ipHead + i) && icmpreply.getHeader().getDstAddr().getHostAddress().equals(srcip)) {
			                     set.add(ipHead + i);
			                 }
			    	}
					}
					
				}else if(b.getClass().getSimpleName().equals("BuildSynpacket")) {
					if(packet.contains(TcpPacket.class)) {
						TcpPacket tcp=packet.get(TcpPacket.class);
						if(tcp.getHeader().getSrcPort()==TcpPort.HTTPS) {
							/**
							 * 	转换成tcp包进行判断，tcp包含端口信息
							 * Convert to tcp packet for judgment， tcp packet contain port information 
							 * 
							 * */
							 counter++;
							IpV4Packet syn=packet.get(IpV4Packet.class);
							 for (int i =tools.getStart(); i <= tools.getEnd(); i++) {
			                        if (syn.getHeader().getSrcAddr().getHostAddress().equals(ipHead + i) && syn.getHeader().getDstAddr().getHostAddress().equals(srcip)) {
			                            set.add(ipHead + i);
			                        }
						}
						}
						}
				}
				}
			    if(counter>=scanIpCount) {
			    	sendHandler.close();
		        	break;
		        }
			}
		} catch (NotOpenException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        pool.shutdownNow();
    	sendHandler.close();
        return set;
    }
    private class timer implements Callable<Boolean>{
    	private final int ipCount;
    	public timer(int ipcount) {
    		this.ipCount=ipcount;
    	}
		@Override
		public Boolean call()  {
			// TODO Auto-generated method stub
			int i=0;
			while(i<ipCount) {
				try {
					/**
					 *	 计时器进程以20毫秒为单位，可调整
					 *	Timer process is adjustable 
					 * 
					 * */
					Thread.sleep(20);
					i++;
				} catch (InterruptedException e) {
					// TODO Auto-generated catch block
					return false;
				}
			
			}
			return true;
		}
    	
    }
}
