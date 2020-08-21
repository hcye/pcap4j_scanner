package com.hcye.myScanner.scanIp;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Set;

public class ShowIpScanResult {
	public static <T> void show(Set<String> s) {
		List<String> list=new ArrayList<String>();
		for (String str:s) {
			list.add(str);
		}
		Collections.sort(list,new Comparator<String>(){
			@Override
			public int compare(String o1, String o2) {
				// TODO Auto-generated method stub
				String ip1 = o1;
				String ip2 = o2;
				String ipSuffix1=ip1.split("\\.")[3];
				String ipSuffix2=ip2.split("\\.")[3];
				Integer intIpSuffix1=Integer.parseInt(ipSuffix1);
				Integer intIpSuffix2=Integer.parseInt(ipSuffix2);
				return intIpSuffix1.compareTo(intIpSuffix2);
			}});
		for(String str:list) {
			System.out.println(str+" alive");
		}
		System.out.println("活动的ip总数是："+list.size());
	}
	
}
