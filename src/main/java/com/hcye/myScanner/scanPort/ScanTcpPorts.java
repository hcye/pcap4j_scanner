package com.hcye.myScanner.scanPort;

import java.net.UnknownHostException;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.packet.namednumber.TcpPort;

import com.hcye.myScanner.Pcap4JTools;
import com.hcye.myScanner.ScanLiveIp;

public class ScanTcpPorts {
	private final TcpPort[] srcPorts;
	private final TcpPort[] dstPorts;
	private final PcapNetworkInterface nif;
	private final int dstIpStartSuffix;
	private final int dstIpEndSuffix;
	private final String dstIpPrefix;
	private final String srcIp;
	private final String dstIps;
	private final String gateway;
	public ScanTcpPorts(TcpPort[] dstPortsRange,String dstIps,PcapNetworkInterface nif,String gateway) {
		this.dstIps=dstIps;
		this.dstPorts=dstPortsRange;
		this.nif=nif;
		this.gateway=gateway;
		Pcap4JTools tools=new Pcap4JTools(dstIps);
		this.dstIpStartSuffix=tools.getStart();
		this.dstIpEndSuffix=tools.getEnd();
		this.dstIpPrefix=tools.getIphead();
		this.srcIp=Pcap4JTools.getIpByNif(nif);
		this.srcPorts=new TcpPort[5];
		/**
		 * 构造一个64800-65100之间的随机5位数组,用于充当源端口
		 * */
		for(int j=0;j<5;j++) {
			short shortDstPort= (short) (Math.random()*300+64800);
			srcPorts[j]=TcpPort.getInstance(shortDstPort);
		}
	}
	public void scanPort() {
		/**
		 * 扫描线程池
		 * */
		ExecutorService pool=Executors.newCachedThreadPool();
		ScanLiveIp scanIp=new ScanLiveIp();
		
		try {
			Set<String> res=scanIp.scan(dstIps, gateway, srcIp);
		} catch (UnknownHostException | PcapNativeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
}
