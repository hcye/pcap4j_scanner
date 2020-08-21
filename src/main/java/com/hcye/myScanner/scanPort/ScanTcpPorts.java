package com.hcye.myScanner.scanPort;

import java.net.UnknownHostException;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;

import com.hcye.myScanner.MyPacketListener;
import com.hcye.myScanner.Pcap4JTools;
import com.hcye.myScanner.SendPacket;
import com.hcye.myScanner.scanIp.ScanLiveIp;
import com.hcye.myScanner.scanIp.ShowIpScanResult;

public class ScanTcpPorts {
	private final int[] dstPorts;
	private final PcapNetworkInterface nif;
	private final String  dstIps;
	private final String gateway;
	private Set<String> liveIps;
	private Object lock;
	private final int timeToRelay;
	public ScanTcpPorts(int[] dstPortsRange,String  dstIps,PcapNetworkInterface nif,String gateway,int timeToRelay) {
		this.dstIps=dstIps;
		this.dstPorts=dstPortsRange;
		this.nif=nif;
		this.gateway=gateway;
		this.lock=new String();
		this.timeToRelay=timeToRelay;
		ScanLiveIp scanIp=new ScanLiveIp(lock);
		try {
			liveIps=scanIp.scan(dstIps, gateway, Pcap4JTools.getIpByNif(nif));
			System.out.println("存活ip扫描完成");
			ShowIpScanResult.show(liveIps);   //打印出扫描到的存活ip
			System.out.println("进入端口扫描进程");
			
		} catch (UnknownHostException | PcapNativeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
	public Set<String> scanPort() throws PcapNativeException, NotOpenException, UnknownHostException, InterruptedException {
		/**
		 * 扫描线程池
		 * */
		this.lock=new String();
		ExecutorService lisenerPool=Executors.newCachedThreadPool();
		LisenerTask ts=new LisenerTask();
		Future<Set<String>> lisennerFuture=lisenerPool.submit(ts);
		SenderTask senderTask=new SenderTask();
		lisenerPool.execute(senderTask);
	    Set<String> res=null;
		try {
			res=lisennerFuture.get();
			return res;
		} catch (InterruptedException | ExecutionException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}finally {
			lisenerPool.shutdownNow();
		}
		return res;
	}
	private class LisenerTask implements Callable<Set<String>>{
		@Override
		public Set<String> call() throws Exception {
			// TODO Auto-generated method stub
			MyPacketListener listener=new MyPacketListener(lock);
			Set<String> res=listener.lisenerForPortScan(liveIps, nif, dstPorts);
			return res;
		}
		
	}
	private class SenderTask implements Runnable{
		
		@Override
		public void run() {
			// TODO Auto-generated method stub
			SendPacket sendPacket=new SendPacket(nif, liveIps, gateway, dstPorts,lock,timeToRelay);
			try {
				sendPacket.sendSynForTcpPort();
			} catch (UnknownHostException | PcapNativeException | InterruptedException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		
	}
	
	/**
	 * 
	 * 数据包发送进程，结束1秒通知侦听进程，停止侦听
	 * 
	 * */
}
