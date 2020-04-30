package main;

import java.io.*;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.*;

public class test{
	static List<String> rex = new ArrayList<>();
	
	public static void main(String[] args) throws IOException {
//		String fileName = "HDFS_2k.log";
        String logFormat = "<Date> <Time> <Pid> <Level> <Component>: <Content>";
        String inDir = "./data";
        String outDir = "./result";
        String fileName = "HDFS_2k.log";
        int Depth = 4;
        double St = 0.5;
        int maxChild = 100;
        List<String> rex = new ArrayList<>();
        rex.add("(blk_-?[0-9]+)");
        rex.add("(/|)([0-9]+\\.){3}[0-9]+(:[0-9]+|)(:|)");
        rex.add("(?<=[^A-Za-z0-9])(\\-?\\+?\\d+)(?=[^A-Za-z0-9])|[0-9]+$");
        Drain drain = new Drain(logFormat,inDir,outDir,Depth,St,maxChild,rex,"offline","");
        drain.parse(fileName);
//		  Drain drain = new Drain(logFormat,outDir,Depth,St,maxChild,rex,false,"online","tree.txt");
//		  System.out.println(drain.onlineParse("081109 203615 148 INFO dfs.DataNode$PacketResponder: PacketResponder 1 for block blk_38865049064139660 terminating"));
//		  System.out.println(drain.onlineParse("081109 203615 148 INFO dfs.DataNode$PacketResponder: PacketResponder 1 for block blk_38865049064139660 terminating"));
			 
		
	}

}