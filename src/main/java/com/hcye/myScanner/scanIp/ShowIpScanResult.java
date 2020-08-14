package com.hcye.myScanner.scanIp;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Set;

public class ShowIpScanResult {
	public static <T> void show(Set<String> s) {
		List<Ip> list=new ArrayList<Ip>();
		for (String str:s) {
			list.add(new Ip(str));
		}
		Collections.sort(list, new Ip("123"));
		for(String str:list) {
			System.out.println(str+" alive");
		}
	}

	private static class Ip implements Comparator<String>{
		private final String ip;
		public Ip(String ip) {
			this.ip=ip;
		}
		@Override
		public String toString() {
			// TODO Auto-generated method stub
			return ip;
		}
		@Override
		public int compare(String o1, String o2) {
			// TODO Auto-generated method stub
			String ip1 = o1;
			String ip2 = o2;
			String ipSuffix1=ip1.split("\\.")[3];
			String ipSuffix2=ip2.split("\\.")[3];
			System.out.println(ipSuffix1);
			int intIpSuffix1=Integer.parseInt(ipSuffix1);
			int intIpSuffix2=Integer.parseInt(ipSuffix2);
			if(intIpSuffix1>intIpSuffix2) {
				return 1;
			}else {
				return 0;
			}
		}
		
	}
}
