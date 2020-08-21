package com.hcye.myScanner;

import java.net.UnknownHostException;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.TcpPort;

import com.hcye.myScanner.inter.PacketBuilder;
import com.hcye.myScanner.packetBuilder.BuildSynpacket;

public class SendPacket {
	private String dstIP="";
	private Set<String> SetDstIps=null;
	private final String gateway;
	private PacketBuilder builder=null;
	private final PcapNetworkInterface nif;
	private int[] tcpDstPorts=null;
	private int[] udpDstPorts=null;
	private Object lock;
	private int timeToRelay;
	/**
	 * 构造函数-》扫描ip
	 * */
	public SendPacket(PcapNetworkInterface nif,String dstIp,String gateway,PacketBuilder builder,Object lock) {
		this.nif=nif;
		this.dstIP=dstIp;
		this.gateway=gateway;
		this.builder=builder;
		this.lock=lock;
	}
	/**
	 *  构造函数-》扫描tcp端口
	 * */
	public SendPacket(PcapNetworkInterface nif,Set<String> SetDstIps,String gateway,int[] dstPorts,Object lock,int timeToRelay) {
		this.nif=nif;
		this.SetDstIps=SetDstIps;
		this.gateway=gateway;
		this.tcpDstPorts=dstPorts;
		this.lock=lock;
		this.timeToRelay=timeToRelay;
	}
	/**
	 * 构造函数-》扫描udp端口
	 * */
	public SendPacket(PcapNetworkInterface nif,Set<String> SetDstIps,String gateway,PacketBuilder builder,int[] dstPorts,Object lock,int timeToRelay) {
		this.nif=nif;
		this.SetDstIps=SetDstIps;
		this.gateway=gateway;
		this.builder=builder;
		this.udpDstPorts=dstPorts;
		this.lock=lock;
		this.timeToRelay=timeToRelay;
	}
	
	public void sendForIpScan() throws PcapNativeException, UnknownHostException, InterruptedException {
		ThreadPoolExecutor pool=new ThreadPoolExecutor(100, 500, 5, TimeUnit.MILLISECONDS, new LinkedBlockingQueue());
		String dstMac="";
		PcapHandle sendHandler=nif.openLive(65536, PromiscuousMode.PROMISCUOUS, 10);
		
		
		/**
		 * 如果不在同一网段，则要解析网关mac地址
		 * 
		 * */
		if(!builder.getClass().getSimpleName().equals("BuildArpPacket")) {	
			
			SendArpRequest arp =new SendArpRequest();
			dstMac=arp.sendArp(gateway,nif);
			
		}
		Pcap4JTools tools=new Pcap4JTools(dstIP);
		int start = tools.getStart();
		int end = tools.getEnd();
		String iphead=tools.getIphead();
		for(int i=start;i<=end;i++) {
			taskForIpScan t=new taskForIpScan(builder, nif, iphead+i, dstMac, sendHandler);
			pool.execute(t);
		}
		pool.shutdown();
		while(true) {
			Thread.sleep(1000);
			if(pool.isShutdown()) {
				synchronized (lock) {
					lock.notify();
				}
				sendHandler.close();
				break;
			}
		}
	}
	/**
	 * 发送一个端口段的syn包去探测Ip
	 * @throws InterruptedException 
	 * 
	 * */
	public void sendSynForTcpPort() throws PcapNativeException, UnknownHostException, InterruptedException {
		ThreadPoolExecutor pool=new ThreadPoolExecutor(100, 500, 5, TimeUnit.MILLISECONDS, new LinkedBlockingQueue());
		if(tcpDstPorts==null) {
			throw new RuntimeException("请选择含目标端口的构造函数");
		}
		String dstMac="";
		PcapHandle sendHandler=nif.openLive(65536, PromiscuousMode.PROMISCUOUS, 10);
		
		/**
		 * 
		 * 判断是否在同一个网段，如果在同一个网段则每个ip都要解析mac地址，不在同一个网段则只需要解析网关mac地址。
		 * 
		 * */
		boolean flag=false;  //同一网段为true
		for(String ip:SetDstIps) {
			flag=Pcap4JTools.isDifferentVlan(ip, gateway);
			break;
		}
		
		if(flag) {   //移除本机ip
			SetDstIps.remove(Pcap4JTools.getIpByNif(nif));
		}
		
		if(!flag){//不在同一网段则解析网关mac地址	
			SendArpRequest arp =new SendArpRequest();
			dstMac=arp.sendArp(gateway,nif);
		}
		TcpPort[] srcPorts=new TcpPort[5];
		
		/**
		 * 
		 * 构造一个64800-65100之间的随机5位数组,用于充当源端口
		 * 
		 * */
		for(int j=0;j<5;j++) {
			short shortDstPort= (short) (Math.random()*300+64800);
			srcPorts[j]=TcpPort.getInstance(shortDstPort);
		}
		
		for(String ip:SetDstIps) {
			if(flag) {//如果在同一个网段则为每个ip地址解析mac地址 
				SendArpRequest arp =new SendArpRequest();
				dstMac=arp.sendArp(ip,nif);
				if(dstMac.length()<15) {   //如果没解析到mac地址则重试一次
					dstMac=arp.sendArp(ip,nif);
				}
				if(dstMac.length()<15) {  //还没解析到就跳过该ip
					continue;
				}
			}
			for(int j=tcpDstPorts[0];j<tcpDstPorts[1];j++) {
				taskForPortScan t=new taskForPortScan(nif, ip, dstMac, sendHandler,j,srcPorts);
				//-------------------------加入随机数，防止防火墙拦截-----------------------------
				int r=(int) (Math.random()*timeToRelay);   
				if(r==0) {
					r=10;
				}
				if(j%r==0) {
					Thread.sleep((long) (Math.random()*timeToRelay)/3);  //
				}
				pool.execute(t);
			}
			
		}
		pool.shutdown();
		while(true) {
			Thread.sleep(1000);
			if(pool.isShutdown()) {
				System.out.println("发送tcp端口探测包执行完毕！！！");
				synchronized (lock) {
					System.out.println("通知监听进程停止监听！");
					lock.notify();
				}
				sendHandler.close();
				break;
			}
		}
		
	}
	private class taskForPortScan implements Runnable{
		//PacketBuilder builder, PcapNetworkInterface nif, String dstip, String dstMac, PcapHandle sendHandle
		private PacketBuilder builder;
		private final PcapNetworkInterface nif;
		private final String dstip;
		private final String dstMac;
		private PcapHandle sendHandle;
		private final int dstPort;
		private final TcpPort[] srcPorts;
		public taskForPortScan(PcapNetworkInterface nif, String dstip, String dstMac, PcapHandle sendHandle,int dstPort,TcpPort[] srcPorts) {
			// TODO Auto-generated constructor stub
			this.nif=nif;
			this.dstip=dstip;
			this.dstMac=dstMac;
			this.sendHandle=sendHandle;
			this.dstPort=dstPort;
			this.srcPorts=srcPorts;
			this.builder=new BuildSynpacket(nif, TcpPort.getInstance((short)dstPort), srcPorts[(int) (Math.random()*4)]);
		}
		@Override
		public void run() {
			// TODO Auto-generated method stub
			try {
				Packet packet=builder.getWholePacket(dstip, dstMac);
				if(!sendHandle.isOpen()) {
					sendHandle=nif.openLive(65536, PromiscuousMode.PROMISCUOUS, 10);
				}
				sendHandle.sendPacket(packet);
			}catch (Exception e) {
				// TODO: handle exception
				System.out.println(e);
			}
		}
		
	}
	private class taskForIpScan implements Runnable {
        private final PcapNetworkInterface nif;
        private final PacketBuilder builder;
        private final String dstip;
        private final String dstMac;
        private PcapHandle sendHandle;

        public taskForIpScan(PacketBuilder builder, PcapNetworkInterface nif, String dstip, String dstMac, PcapHandle sendHandle) {
            this.nif = nif;
            this.builder = builder;
            this.dstip = dstip;
            this.dstMac = dstMac;
            this.sendHandle = sendHandle;
        }

        /**
         * When an object implementing interface <code>Runnable</code> is used
         * to create a thread, starting the thread causes the object's
         * <code>run</code> method to be called in that separately executing
         * thread.
         * <p>
         * The general contract of the method <code>run</code> is that it may
         * take any action whatsoever.
         *
         * @see Thread#run()
         */
        @Override
        public void run() {
        	/**
        	 * 如果是发送arp请求，不需要目标mac地址，这里目标mac地址是空字符串""，
        	 * 如果不发arp请求，则由于扫描地址不在同一网段，这里mac地址是网关mac地址。
        	 * */
            Packet packet;
            try {
                packet = builder.getWholePacket(dstip,dstMac);    
                if (!sendHandle.isOpen()) {
                    sendHandle = nif.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10);
                }
                /**
                 * 
                 *	 每个请求发送两次
                 *	Two per request 
                 *
                 * */
                for(int i=0;i<2;i++) {
                	 sendHandle.sendPacket(packet);
                }
            } catch (UnknownHostException e) {
                e.printStackTrace();
            } catch (PcapNativeException e) {
                e.printStackTrace();
            } catch (NotOpenException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} 
            

        }
    }
}
