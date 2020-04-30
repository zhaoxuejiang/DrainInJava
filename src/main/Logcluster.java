package main;

import java.util.*;
import java.io.Serializable;

public class Logcluster implements Serializable{
	

	private static final long serialVersionUID = 4344085662143848082L;
	List<String> logTemplate = new ArrayList<>();
	List<Integer> logIDL = new ArrayList<>();
	
	public Logcluster(){
	}
	
	public void addLogId(int id) {
		logIDL.add(id);
	}
	public void setTemplate(List<String> logtemplate) {
		logTemplate = logtemplate;
	}
}