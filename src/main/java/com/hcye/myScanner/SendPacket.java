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
import org.pcap4j.packet.namednumber.Port;
import org.pcap4j.packet.namednumber.TcpPort;
import org.pcap4j.packet.namednumber.UdpPort;

import com.hcye.myScanner.inter.PacketBuilder;
import com.hcye.myScanner.packetBuilder.BuildSynpacket;
import com.hcye.myScanner.packetBuilder.BuildUdpPacket;

public class SendPacket {
	private String dstIP="";
	private Set<String> SetDstIps=null;
	private final String gateway;
	private PacketBuilder builder=null;
	private final PcapNetworkInterface nif;
	private int[] dstPorts=null;
	private Object lock;
	private int timeToRelay;
	public static final String TCP="TCP";
	public static final String UDP="UDP";
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
	 *  构造函数-》扫描端口
	 * */
	public SendPacket(PcapNetworkInterface nif,Set<String> SetDstIps,String gateway,int[] dstPorts,Object lock,int timeToRelay) {
		this.nif=nif;
		this.SetDstIps=SetDstIps;
		this.gateway=gateway;
		this.dstPorts=dstPorts;
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
	 * 
	 * 
	 * */
	
	public void sendPacketForPortScan(String PortType) throws Exception {
		ThreadPoolExecutor pool=new ThreadPoolExecutor(100, 500, 5, TimeUnit.MILLISECONDS, new LinkedBlockingQueue());
		if(dstPorts==null) {
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
		
		if(flag) {   //如果扫描同一网段，移除本机IP，不扫描本机
			SetDstIps.remove(Pcap4JTools.getIpByNif(nif));
		}
		
		if(!flag){//不在同一网段则解析网关mac地址	
			SendArpRequest arp =new SendArpRequest();
			dstMac=arp.sendArp(gateway,nif);
		}
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
			for(int j=dstPorts[0];j<=dstPorts[1];j++) {
				
				//-------------------------加入随机数，防止防火墙拦截-----------------------------
				int r=(int) (Math.random()*timeToRelay);   
				if(r==0) {
					r=10;
				}
				if(j%r==0) {
					Thread.sleep((long) (Math.random()*timeToRelay)/3);  //
				}
				taskForPortSCan tfp=new taskForPortSCan(ip, dstMac,j,srcPorts,sendHandler,PortType);
				pool.execute(tfp);
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
	private class taskForPortSCan implements Runnable{

		//PacketBuilder builder, PcapNetworkInterface nif, String dstip, String dstMac, PcapHandle sendHandle
		private PacketBuilder builder;
		private final String dstip;
		private final String dstMac;
		private PcapHandle sendHandle;
		private final int dstPort;
		private final int[] srcPorts;
		public taskForPortSCan(String dstip, String dstMac,int dstPort,int[] srcPorts,PcapHandle sendHandle,String portType) throws Exception {
			// TODO Auto-generated constructor stub
			this.dstip=dstip;
			this.dstMac=dstMac;
			this.dstPort=dstPort;
			this.srcPorts=srcPorts;
			this.sendHandle=sendHandle;
			if(portType.equals(SendPacket.TCP)) {
				this.builder=new BuildSynpacket(nif, dstPort,srcPorts[(int) (Math.random()*4)]);
			}else if(portType.equals(SendPacket.UDP)) {
				this.builder=new BuildUdpPacket(nif, dstPort,srcPorts[(int) (Math.random()*4)]);
			}
	
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
