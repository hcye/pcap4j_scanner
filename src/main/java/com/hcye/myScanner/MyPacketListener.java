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
	private Object lock;
	public MyPacketListener(Object lock) {
		this.lock=lock;
	}
	public Set<String> lisenerForIpScan(String dstip, PcapNetworkInterface nif, List<PacketBuilder> builder)
			throws PcapNativeException {
		Pcap4JTools tools = new Pcap4JTools(dstip);
		String srcip = Pcap4JTools.getIpByNif(nif);
		Set<String> set = new HashSet<>();
		PcapHandle.Builder handleBuilder = new PcapHandle.Builder(nif.getName()).snaplen(65536)
				.promiscuousMode(PromiscuousMode.PROMISCUOUS).timeoutMillis(10).bufferSize(1024 * 1024 * 10);
		PcapHandle Handler = handleBuilder.build();
		String ipHead = tools.getIphead();
		ExecutorService pool = Executors.newSingleThreadExecutor();    //单线程
		int ipCountNeedfilt=(tools.getEnd()-tools.getStart())*4;    //ip探测同网段只发arp包，跨网段则要发4种数据包。这里按照4种数据包算，这个值用来计算线程等待时间
		CloserTask t = new CloserTask(lock,ipCountNeedfilt);
		
		Future<Boolean> f = pool.submit(t);
		try {
			while (!f.isDone()) {
				Packet packet = Handler.getNextPacket();
				if (packet == null) {
					continue;
				}
				for (PacketBuilder b : builder) {
					if (b.getClass().getSimpleName().equals("BuildArpPacket")) {
						if (packet.contains(ArpPacket.class)) {
							ArpPacket arp = packet.get(ArpPacket.class);
							if (arp.getHeader().getOperation() == ArpOperation.REPLY) {
								/**
								 * 转换成arp包，过滤reply包 Convert to arp packet to judge
								 * 
								 */
								for (int i = tools.getStart(); i <= tools.getEnd(); i++) {
									if (arp.getHeader().getSrcProtocolAddr().getHostAddress().equals(ipHead + i))
										set.add(ipHead + i);
								}
							}
						}
					} else if (b.getClass().getSimpleName().equals("BuildIcmpPacket")
							|| b.getClass().getSimpleName().equals("BuildTimeStampPacket")) {
						if (packet.contains(IcmpV4EchoReplyPacket.class)
								|| packet.contains(IcmpV4TimestampReplyPacket.class)) {
							IpV4Packet icmpreply = packet.get(IpV4Packet.class);
							/**
							 * 转换成IPv4包进行判断 Convert to ipv4 packet to judge
							 */
							for (int i = tools.getStart(); i <= tools.getEnd(); i++) {
								if (icmpreply.getHeader().getSrcAddr().getHostAddress().equals(ipHead + i)) {
									set.add(ipHead + i);
								}
							}
						}

					} else if (b.getClass().getSimpleName().equals("BuildSynpacket")) {
						if (packet.contains(TcpPacket.class)) {
							TcpPacket tcp = packet.get(TcpPacket.class);
							if (tcp.getHeader().getSrcPort() == TcpPort.HTTPS) {
								/**
								 * 转换成tcp包进行判断，tcp包含端口信息 Convert to tcp packet for judgment， tcp packet contain
								 * port information
								 * 
								 */
								IpV4Packet syn = packet.get(IpV4Packet.class);
								for (int i = tools.getStart(); i <= tools.getEnd(); i++) {
									if (syn.getHeader().getSrcAddr().getHostAddress().equals(ipHead + i)) {
										set.add(ipHead + i);
									}
								}
							}
						}
					}
				}
			}
		} catch (NotOpenException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		pool.shutdownNow();
		Handler.close();
		return set;
	}

	public Set<String> lisenerForPortScan(Set<String> dstips, PcapNetworkInterface nif, int[] dstPortRange)
			throws PcapNativeException, NotOpenException {
		Set<String> set = new HashSet<>();
		PcapHandle.Builder handleBuilder = new PcapHandle.Builder(nif.getName()).snaplen(65536)
				.promiscuousMode(PromiscuousMode.PROMISCUOUS).timeoutMillis(20).bufferSize(1024 * 1024 * 100);
		PcapHandle handler = handleBuilder.build();

		
		ExecutorService pool = Executors.newSingleThreadExecutor();
		int PacketCountNeedFilt=(dstips.size()*(dstPortRange[1]-dstPortRange[0]));    //tcp端口探测发送端口数量乘以ip数量的数据包，这个值用来计算线程等待时间
		CloserTask t = new CloserTask(lock,PacketCountNeedFilt);
		Future<Boolean> f = pool.submit(t);
		while (!f.isDone()) {
			Packet p = handler.getNextPacket();
			TcpPacket tcpPacket = null;
			IpV4Packet ipv4Packet = null;
			if (p == null) { // 空数据包跳过
				continue;
			}
			if (p.contains(TcpPacket.class)) { // 如果是tcp包进入下一步判断，否则跳过
				tcpPacket = p.get(TcpPacket.class);
				if (p.contains(IpV4Packet.class)) {
					ipv4Packet = p.get(IpV4Packet.class);
					boolean flag = false;
					for (String ip : dstips) { // 判断数据包源ip在不在传入的目标ip集合里面 ,如果不在的话跳过
						if (ip.equals(ipv4Packet.getHeader().getSrcAddr().getHostAddress())) {
							flag = true;
							break;
						}
					}
					if (!flag) {
						continue;
					}
				}
				if (tcpPacket.getHeader().getRst() == true&&tcpPacket.getHeader().getAck()==true) { // 返回rst+ack包表示端口关闭，跳过
					continue;
				} else {
					TcpPort port = tcpPacket.getHeader().getSrcPort(); // 获得目标端口
					String ip = ipv4Packet.getHeader().getSrcAddr().getHostAddress(); // 获得目标ip
					set.add(ip + ":" + port.valueAsInt() + "-" + port.name()); // 组装成字符串加入set集合
				}
			} else {
				continue;
			}
		}
		System.out.println("数据包侦听执行完毕！！！");
		pool.shutdownNow();
		handler.close();
		return set;
	}

	/**
	 * 
	 * 计时器
	 * 
	 */
	private class CloserTask implements Callable<Boolean> {
		/*
		 * private final int ipCount; private final String type; public timer(int
		 * ipcount,String type) { this.ipCount=ipcount; this.type=type; }
		 * 
		 * @Override public Boolean call() { // TODO Auto-generated method stub int i=0;
		 * while(i<ipCount) { try {
		 *//**
			*	
			* 
			* */
		/*
		 * if(type.equals("tcp")) { //如果是扫描tcp端口计时器间隔1毫秒 Thread.sleep(1); }
		 * if(type.equals("ip")) { //如果是扫描活动的ip则计时器间隔20毫秒 Thread.sleep(20); } i++; }
		 * catch (InterruptedException e) { // TODO Auto-generated catch block return
		 * false; }
		 * 
		 * } return true; }
		 * 
		 */
		private Object lock;
		private int PacketCountNeedFilt;
		public CloserTask(Object lock,int PacketCountNeedFilt) {
			this.lock=lock;
			this.PacketCountNeedFilt=PacketCountNeedFilt;
		}
		@Override
		public Boolean call() throws Exception {
			// TODO Auto-generated method stub
			synchronized (lock) {
				lock.wait();
				Thread.sleep(PacketCountNeedFilt/8);   //等待过滤回包完成
				return true;
			}
		}
		
	}
}
