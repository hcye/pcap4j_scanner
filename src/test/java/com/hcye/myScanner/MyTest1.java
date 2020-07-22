package com.hcye.myScanner;
import java.net.UnknownHostException;
import org.pcap4j.core.PcapNativeException;
public class MyTest1 {
	public static void main(String[] args) throws UnknownHostException, PcapNativeException {
		String dstIp="10.75.60.1/24"; //目标网段   Target segment 
		String gateway="10.75.60.1";  //网关 gateway
		String myInterIp="10.75.60.155";//我的网卡地址 My network card address 
		ScanLiveIp scan=new ScanLiveIp();
		scan.scan(dstIp, gateway, myInterIp);
	}
}
