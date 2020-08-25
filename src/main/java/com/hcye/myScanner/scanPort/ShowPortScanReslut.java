package com.hcye.myScanner.scanPort;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class ShowPortScanReslut {
	public static void show(Set<String> res) {
		/**
		 * 构造一个set数组，用于存放不同ip的扫描结果
		 * */
		List<List<String>> resss=new ArrayList<List<String>>();
		Set<String> resIp1=new HashSet<String>();
		/**
		 * 先获得不重复的ip数组,set去重
		 * */
		for(String str:res) {
			String[] strs=str.split(":");
			resIp1.add(strs[0]);
		}
		List<String> resIp=new ArrayList<String>();
		for(String s:resIp1) {
			resIp.add(s);
		}
		Collections.sort(resIp, new Comparator<String>() {
			@Override
			public int compare(String o1, String o2) {
				// TODO Auto-generated method stub
				Integer suffix1=Integer.parseInt(o1.split("\\.")[3]);
				Integer suffix2=Integer.parseInt(o2.split("\\.")[3]);
				return suffix1.compareTo(suffix2);
			}
			
		});
		
		List<String> ress=null;
		for(String ip:resIp) {
			ress=new ArrayList<String>();
			for(String str:res) {
				if(ip.equals(str.split(":")[0])) {
					ress.add(str);
				}
			}
			Collections.sort(ress, new Comparator<String>() {
				@Override
				public int compare(String o1, String o2) {
					// TODO Auto-generated method stub
					Integer suffix1=Integer.parseInt(o1.split(":")[1].split("-")[0]);
					Integer suffix2=Integer.parseInt(o2.split(":")[1].split("-")[0]);
					return suffix1.compareTo(suffix2);
				}
			});
			resss.add(ress);
		}
		for(List<String> s:resss) {
			for(String ss:s) {
				System.out.println(ss);
			}
		}
	}
}
