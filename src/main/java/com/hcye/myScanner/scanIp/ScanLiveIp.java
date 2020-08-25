package com.hcye.myScanner.scanIp;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.namednumber.TcpPort;

import com.hcye.myScanner.MyPacketListener;
import com.hcye.myScanner.Pcap4JTools;
import com.hcye.myScanner.SendPacket;
import com.hcye.myScanner.inter.PacketBuilder;
import com.hcye.myScanner.packetBuilder.BuildArpPacket;
import com.hcye.myScanner.packetBuilder.BuildIcmpPacket;
import com.hcye.myScanner.packetBuilder.BuildSynpacket;
import com.hcye.myScanner.packetBuilder.BuildTimeStampPacket;

public class ScanLiveIp {
	/*
	 * String dstIp="10.75.70.1/24"; //目标网段 String gateway="10.75.60.1"; //网关 String
	 * myInterIp="10.75.60.155";//我的网卡地址
	 */	
	private Object lock;
	public ScanLiveIp(Object lock) {
		this.lock=lock;
	}
	public Set<String> scan(String dstIp,String gateway,String myInterIp) throws UnknownHostException, PcapNativeException {
		PcapNetworkInterface nif=Pcaps.getDevByAddress(InetAddress.getByName(myInterIp));
		Pcap4JTools tools=new Pcap4JTools(dstIp);
		Future<Set<String>> f=null;
		ExecutorService pool=Executors.newCachedThreadPool();
		List<PacketBuilder> builders=new ArrayList<PacketBuilder>();
		int dstPort=443;
		int[] srcPorts=new int[5];
		
		/**
		 * 
		 * 构造一个64800-65100之间的随机5位数组,用于充当源端口
		 * 
		 * */
		for(int j=0;j<5;j++) {
			short shortDstPort= (short) (Math.random()*300+64800);
			srcPorts[j]=shortDstPort;
		}
		
		/**
		 * 判断是否是同一个网段
		 * 此处默认按照 24位掩码判断，对于自身广播域掩码小于24位时会出现部分地址扫描不到的情况，可以对 所有目标地址广播arp请求，如果返回true则认定同一网段。
		 * 没有arp reply 地址的默认为不同网段发送 icmp syn timestamp 请求。
		 * 
		 * */
		if(Pcap4JTools.isDifferentVlan(dstIp, gateway)) {
			PacketBuilder arpBuilder = (PacketBuilder) new BuildArpPacket(nif);
			builders.add(arpBuilder);
		}else {
			PacketBuilder icmpBuilder=new BuildIcmpPacket(nif);
			PacketBuilder timstamp=(PacketBuilder) new BuildTimeStampPacket(nif);
			PacketBuilder synPacket=new BuildSynpacket(nif,dstPort,srcPorts[(int)Math.random()*4]);
			builders.add(icmpBuilder);
			builders.add(timstamp);
			builders.add(synPacket);
		}
//		PcapNetworkInterface nif,String dstIp,String gateway,ExecutorService pool,PacketBuilder builder
		
		for(PacketBuilder b:builders) {
			task t=new task(dstIp,nif,builders);
			f=pool.submit(t);
			task1 t1=new task1(nif,dstIp,gateway,b);
			pool.execute(t1);
		}
		
		Set<String> s=new HashSet<String>();
		try {
			s=f.get();
			return s;
			
		} catch (InterruptedException | ExecutionException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}finally {
			pool.shutdownNow();
		}
		return s;
	}
	
	

	
private class task implements Callable<Set<String>>{
	private final String dstip;
	private final PcapNetworkInterface nif;
	private final List<PacketBuilder> builder;
	public task(String dstip,PcapNetworkInterface nif,List<PacketBuilder> builder) {
		this.dstip=dstip;
		this.nif=nif;
		this.builder=builder;
	}
	@Override
	public Set<String> call() throws Exception {
		// TODO Auto-generated method stub
		MyPacketListener listener=new MyPacketListener(lock);
		Set<String> set=listener.lisenerForIpScan(dstip, nif, builder);
		return set;
	}
}
private class task1 implements Runnable{
//	nif, dstIp,gateway, pool,icmpBuilder
	private final PcapNetworkInterface nif;
	private final String dstIp;
	private final String gateway;
	private final PacketBuilder builder;
	public task1(PcapNetworkInterface nif,String dstIp,String gateway,PacketBuilder builder) {
		this.nif=nif;
		this.dstIp=dstIp;
		this.gateway=gateway;
		this.builder=builder;
	}
	@Override
	public void run() {
		// TODO Auto-generated method stub
		SendPacket sendPacket=new SendPacket(nif, dstIp,gateway,builder,lock);
		try {
			sendPacket.sendForIpScan();
		} catch (UnknownHostException | PcapNativeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
}

}
