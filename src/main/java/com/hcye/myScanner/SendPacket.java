package com.hcye.myScanner;

import java.net.UnknownHostException;
import java.util.concurrent.ExecutorService;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.packet.Packet;

public class SendPacket {
	private final String dstIP;
	private final String gateway;
	private final PacketBuilder builder;
	private final PcapNetworkInterface nif;
	private final ExecutorService pool;
	public SendPacket(PcapNetworkInterface nif,String dstIp,String gateway,ExecutorService pool,PacketBuilder builder) {
		this.nif=nif;
		this.dstIP=dstIp;
		this.pool=pool;
		this.gateway=gateway;
		this.builder=builder;
	}
	public void send() throws PcapNativeException, UnknownHostException {
		String dstMac="";
		PcapHandle sendHandler=nif.openLive(65536, PromiscuousMode.PROMISCUOUS, 10);
		if(!builder.getClass().getSimpleName().equals("BuildArpPacket"))
		{	SendArpRequest arp =new SendArpRequest();
			dstMac=arp.sendArp(gateway,nif);
		}
		Pcap4JTools tools=new Pcap4JTools(dstIP);
		int start = tools.getStart();
		int end = tools.getEnd();
		String iphead=tools.getIphead();
		for(int i=start;i<=end;i++) {
			task t=new task(builder, nif, iphead+i, dstMac, sendHandler);
			pool.execute(t);
		}
	}
	private class task implements Runnable {
        private final PcapNetworkInterface nif;
        private final PacketBuilder builder;
        private final String dstip;
        private final String dstMac;
        private PcapHandle sendHandle;

        public task(PacketBuilder builder, PcapNetworkInterface nif, String dstip, String dstMac, PcapHandle sendHandle) {
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
