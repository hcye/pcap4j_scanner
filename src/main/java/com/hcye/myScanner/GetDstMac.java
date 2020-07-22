package com.hcye.myScanner;


import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;

import java.util.concurrent.ExecutorService;

public class GetDstMac {
    public String getDstMac(String dstIp, String gatewayIp, PcapNetworkInterface nif, PcapHandle sendHandle) throws PcapNativeException {
        final String srcip=Pcap4JTools.getIpByNif(nif);
        SendArpRequest sendArpRequest=new SendArpRequest();
        String dstMac=null;
        String[] strs= srcip.split("\\.");
        String[] strs1= dstIp.split("\\.");
        /*
         * 	判断是否同一网段
         *	Determine whether the same network segment 
         * 
         * */
        if(strs[0].equals(strs1[0])&&strs[1].equals(strs1[1])&&strs[2].equals(strs1[2])){
            dstMac=sendArpRequest.sendArp(dstIp,nif);
   
            return dstMac;
        }else {
     
            dstMac=sendArpRequest.sendArp(gatewayIp,nif);
            return dstMac;
        }

    }
}
