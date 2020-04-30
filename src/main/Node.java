package main;

import java.util.*;
import java.io.Serializable;


public class Node implements Serializable{

	
	/**
	 * 
	 */
	private static final long serialVersionUID = 7193143456988905954L;
	Map<String,Node> childD = new HashMap<String,Node>();
	int Depth;
	int Digit;
	String Token;
	List<Logcluster> childClu = new ArrayList<>();
	
	public Node(){
		Depth = 0;
	}
	
	public void addChildNode(String key,Node child) {
		childD.put(key,child);
	}
	
	public void setDigit(int digit) {
		Digit = digit;
	}
	
	public void setToken(String token) {
		Token = token;
	}
	
	public void setDepth(int dep) {
		Depth = dep;
	}
	
	public void addChildClu(Logcluster cluster) {
		childClu.add(cluster);
	}
	
}