package com.hcye.myScanner;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Set;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;

import com.hcye.myScanner.scanIp.ScanLiveIp;
import com.hcye.myScanner.scanIp.ShowIpScanResult;
import com.hcye.myScanner.scanPort.ScanPorts;
import com.hcye.myScanner.scanPort.ShowPortScanReslut;
public class MyTest1 {
	public static void main(String[] args) throws UnknownHostException, PcapNativeException, NotOpenException, InterruptedException {
		scanTcpPort();
	}
	private static void scanIp() {
		Object lock=new String();
		String dstIp="10.75.100.1/25"; //目标网段   Target segment 
		String gateway="10.75.60.1";  //网关 gateway
		String myInterIp="10.75.60.155";//我的网卡地址 My network card address 
		ScanLiveIp scan=new ScanLiveIp(lock);
		try {
			ShowIpScanResult.show(scan.scan(dstIp, gateway, myInterIp));
		} catch (UnknownHostException | PcapNativeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	private static void scanTcpPort() throws NotOpenException, InterruptedException {
		String dstIp="172.32.0.202"; //目标网段   Target segment portType
		String gateway="10.75.60.1";  //网关 gateway
		String myInterIp="10.75.60.155";//我的网卡地址 My network card address 
		int timeToRelay=0;              //数据包发送延时参数，此参数大小不代表速度快慢
		int[] dstPortsRange= {54321,54322}; //端口目标端口范围
		PcapNetworkInterface nif;
		try {
			nif = Pcaps.getDevByAddress(InetAddress.getByName(myInterIp));
			ScanPorts sc=new ScanPorts(dstPortsRange, dstIp, nif, gateway,timeToRelay);
			Set<String> res=sc.scanPort(SendPacket.UDP);
			ShowPortScanReslut.show(res);
		} catch (UnknownHostException | PcapNativeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
}
