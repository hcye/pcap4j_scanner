package com.hcye.myScanner;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.pcap4j.core.*;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.util.MacAddress;

import com.hcye.myScanner.packetBuilder.BuildArpPacket;


/**
 * 
 * 发送arp包，解析mac地址
 * 
 * */
public class SendArpRequest {
    public SendArpRequest() {
    }
    @SuppressWarnings("finally")
	public String sendArp(String strDstIpAddress, PcapNetworkInterface nif) throws PcapNativeException  {
        final String srcIpAddress = Pcap4JTools.getIpByNif(nif);
        PcapHandle sendHandle=nif.openLive(65536, PromiscuousMode.PROMISCUOUS, 10);
        ExecutorService pool=Executors.newSingleThreadExecutor();
         MacAddress[] resolvedAddr = new MacAddress[1];
        try {

            PacketListener listener = new PacketListener() {
                @Override
                public void gotPacket(PcapPacket pcapPacket) {
                    if (pcapPacket.contains(ArpPacket.class)) {
                        ArpPacket arp = pcapPacket.get(ArpPacket.class);
                        if (arp.getHeader().getDstProtocolAddr().getHostAddress().equals(srcIpAddress) && arp.getHeader().getSrcProtocolAddr().getHostAddress().equals(strDstIpAddress)) {
                            try {
                                resolvedAddr[0] = arp.getHeader().getSrcHardwareAddr();
                                sendHandle.breakLoop();
                            } catch (NotOpenException e) {
                                e.printStackTrace();
                            }
                        }
                    }
                }
            };
            Task t = new Task(sendHandle, listener, nif);
            BuildArpPacket arp=new BuildArpPacket(nif);
            pool.execute(t);
            Packet p = arp.getWholePacket(strDstIpAddress, "");
            sendHandle.sendPacket(p);
        } finally {
            pool.shutdown();
            try {
                pool.awaitTermination(400, TimeUnit.MILLISECONDS);  //如果400毫秒解析到地址中断进程
                if (sendHandle != null && sendHandle.isOpen()) {
                    sendHandle.breakLoop();
                    sendHandle.close();
                }
                if (pool != null && !pool.isShutdown()) {
                    pool.shutdownNow();
                }
            } catch (InterruptedException | NotOpenException e) {
                return "";
            }
            if (resolvedAddr[0] != null) {
                return resolvedAddr[0].toString();
            } else {
                return "";
            }
        }
    }

    private static class Task implements Runnable {

        private PcapHandle handle;
        private PacketListener listener;
        private PcapNetworkInterface nif;

        public Task(PcapHandle handle, PacketListener listener, PcapNetworkInterface nif) {
            this.handle = handle;
            this.listener = listener;
            this.nif = nif;
        }

        @Override
        public void run() {
            try {
                if (!handle.isOpen()) {
                    handle = nif.openLive(65536, PromiscuousMode.PROMISCUOUS, 10);
                }
                handle.loop(-1, listener);
            } catch (PcapNativeException e) {
                e.printStackTrace();
            } catch (InterruptedException e) {
            } catch (NotOpenException e) {
                e.printStackTrace();
            }
        }
    }
}
