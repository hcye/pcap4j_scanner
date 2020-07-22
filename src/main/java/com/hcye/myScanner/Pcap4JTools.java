package com.hcye.myScanner;


import org.pcap4j.core.PcapAddress;
import org.pcap4j.core.PcapNetworkInterface;

public class Pcap4JTools { 
   private  int start;
   private  int end;
   private  String iphead;
   private  String mask;
   private String startIp;
   
public int getStart() {
	return start;
}

public int getEnd() {
	return end;
}

public String getIphead() {
	return iphead;
}

public String getMask() {
	return mask;
}

public String getStartIp() {
	return startIp;
}

   public Pcap4JTools(String dstip) {
	// TODO Auto-generated constructor stub
	   int end1=0;
       String[] dstips;
       String mask1="";
       String ipheadString;
       int start1;
       String startIp;
       if (dstip.contains("/")) {
           dstips = dstip.split("/");
           mask1 = dstips[1];
           startIp = dstips[0];
       } else {
    	   mask1 = "32";
           startIp = dstip;
       }
       try {
           Integer.parseInt(mask1);
       } catch (NumberFormatException e) {
    	   System.out.print("----");
           return;
       }
       String[] ips = startIp.split("\\.");
       if (ips.length != 4) {
    	   System.out.print("--1--");
           return;
       }
       ipheadString=ips[0]+"."+ips[1]+"."+ips[2]+".";
       start1=Integer.parseInt(ips[3]);
       if (mask1.equals("32") || Integer.parseInt(mask1) > 32 || Integer.parseInt(mask1) < 1) {
    	   end1 = Integer.parseInt(ips[3]);
       } else {
    	   end1 = (int) (Integer.parseInt(ips[3]) + Math.pow(2, (32 - Integer.parseInt(mask1))));
           if (end1 > 255) {
        	   end1 = 255;
           } else {
        	   /**
        	    * 
        	    * 	剔除广播地址
        	    *	 Remove broadcast address 
        	    * */
        	   end1 = end1 - 1;
           }
       }
       this.startIp=ipheadString+start1;
	   this.end=end1;
	   this.mask=mask1;
	   this.start=start1;
	   this.iphead=ipheadString;
}



public static String getIpByNif(PcapNetworkInterface nif) {

	for(PcapAddress ad:nif.getAddresses()) {
		if(ad.getAddress().getHostAddress().length()<=15) {
			return ad.getAddress().getHostAddress();
		}
	}
	return "";
}
public static String getMacByNif(PcapNetworkInterface nif) {
	return nif.getLinkLayerAddresses().get(0).toString();
	
}

public boolean isDifferentVlan(String dstIp,String gateway){
       String[] dstIps= dstIp.split("\\.");
       String[] gateways=gateway.split("\\.");
       String dstIpHead=dstIps[0]+dstIps[1]+dstIps[2];
       String gatewayHead=gateways[0]+gateways[1]+gateways[2];
       if(dstIpHead.equals(gatewayHead)){
           return true;
       }else {
           return false;
       }
   }
}
