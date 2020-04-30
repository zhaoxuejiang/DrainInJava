package main;

import java.util.*;
import java.io.*;
import java.util.regex.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

class Result{
	int numOfPar;
	double retVal;
	public Result(int numofpar,double retval) {
		numOfPar = numofpar;
		retVal = retval;
	}
}
public class Drain {
	
	String logFormat;
	String inDir;
	String outDir;
	String logName;
	int depth;
	double St;
	int maxChild;
	List<String> rex = new ArrayList<>();
	List<String> headers = new ArrayList<>();
	List<List<String>> logMessages = new ArrayList<>();
	String Mode;
	String treeFile;
	Node rootNode = new Node();
	Pattern parsePattern;
	private static final char[] HEX_DIGITS = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd',
	        'e', 'f' };
	
	public static String getMD5String(String str) {
        MessageDigest messageDigest = null;
        try {
            messageDigest = MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
        messageDigest.update(str.getBytes());
        return byteArray2HexString(messageDigest.digest());
    }
	
	private static String byteArray2HexString(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(HEX_DIGITS[(b & 0xf0) >> 4]).append(HEX_DIGITS[(b & 0x0f)]);
        }
        return sb.toString();
	}

	
	public Drain(String logformat,String indir,String outdir,int dep,double st,
			int maxchild,List<String> regex,String mode,String treefile){
		logFormat = logformat;
		inDir = indir;
		outDir = outdir;
		depth = dep-2;
		St = st;
		maxChild = maxchild;
		rex = regex;
		Mode = mode;
		treeFile =  treefile;
	}
	
	public Drain(String logformat,String outdir,int dep,double st,int maxchild,
			List<String> regex,String mode,String treefile) {
		logFormat = logformat;
		outDir = outdir;
		depth = dep-2;
		St = st;
		maxChild = maxchild;
		rex = regex;
		Mode = mode;
		treeFile = treefile;
		loadTree();
	}
	
	public static boolean isNumeric(String str){  
		  for (int i = str.length();--i>=0;){    
		   if (!Character.isDigit(str.charAt(i))){  
		    return false;  
		   }  
		  }  
		  return true;  
		}  
	
	public void parse(String logname) {
		long startTime = System.currentTimeMillis(); 
		int count = 0;
		logName = logname;
		System.out.println("Parsing file:"+inDir+logName);
		
		List<Logcluster> logCluL = new ArrayList<>();
		List<String> logMessageL = new ArrayList<>();
		
		File file = new File(outDir);
		if (!file.exists()) {
			file.mkdir();
		}
		
		loadData();
		for(int i=0;i<logMessages.size();i++) {
			int logID = i;
			logMessageL = Arrays.asList(preprocess(logMessages.get(i).get(headers.indexOf("Content"))).split(" "));
			Logcluster matchCluster = treeSearch(rootNode,logMessageL);
			
			if(matchCluster.logTemplate.size() == 0) {
				Logcluster newCluster = new Logcluster();
				newCluster.addLogId(logID);
				newCluster.setTemplate(logMessageL);
				logCluL.add(newCluster);
				addSeqToPrefixTree(rootNode,newCluster);
			}
			else {
				List<String> newTemplate = getTemplate(logMessageL, matchCluster.logTemplate);
				matchCluster.addLogId(logID);
				if(!compareStrArray(newTemplate,matchCluster.logTemplate)) {
					matchCluster.setTemplate(newTemplate);
				}
				
			}
			count+=1;
			if(count%1000==0|| count==logMessages.size()) {
				System.out.printf("Processed %.1f%% of log lines.\n",(count*100.0)/logMessages.size());
			}
		}
		
		
		outputResult(logCluL);
		long endTime = System.currentTimeMillis(); 
		System.out.printf("Parsing done. [Time taken: %s ms]",endTime-startTime);
		
		try {
			ObjectOutputStream oos=new ObjectOutputStream(new FileOutputStream("tree.txt")); 
			oos.writeObject(rootNode);
			oos.close();  
		} catch(FileNotFoundException e) {
			e.printStackTrace();  
		}catch (IOException e) {   
            e.printStackTrace();  
        }  
	}
	
	public String onlineParse(String logLine) {
		List<String> logMessageL = new ArrayList<>();
		Matcher matcher = parsePattern.matcher(logLine); 
		Logcluster logClu = new Logcluster();
		if(matcher.matches()) {
			logMessageL = new ArrayList<>();
			for(int i=1;i<headers.size();i++) {
				logMessageL.add(matcher.group(headers.get(i)));
			}
		}
		logMessageL = Arrays.asList(preprocess(logMessageL.get(headers.indexOf("Content")-1)).split(" "));
		Logcluster matchCluster = treeSearch(rootNode,logMessageL);
		if(matchCluster.logTemplate.size() == 0) {
			Logcluster newCluster = new Logcluster();
			newCluster.setTemplate(logMessageL);
			logClu = newCluster;
			addSeqToPrefixTree(rootNode,newCluster);
		}
		else {
			List<String> newTemplate = getTemplate(logMessageL, matchCluster.logTemplate);
			if(!compareStrArray(newTemplate,matchCluster.logTemplate)) {
				matchCluster.setTemplate(newTemplate);
			}
			logClu = matchCluster;
		}
		return listToStr(logClu.logTemplate);
	}
	
	public void outputResult(List<Logcluster> logClustL) {
		Map<Integer,String> logTemplates = new HashMap<>();
		Map<Integer,String> logTemplateIds = new HashMap<>();
		List<List<String>> eventMessages = new ArrayList<>();
		for(int i=0;i<logClustL.size();i++) {
			String templateStr = listToStr(logClustL.get(i).logTemplate);
			int occurrence = logClustL.get(i).logIDL.size();
			String templateId = getMD5String(templateStr).substring(0,8);
			for(int j=0;j<logClustL.get(i).logIDL.size();j++) {
				int logID = logClustL.get(i).logIDL.get(j)+1;
				logTemplates.put(logID, templateStr);
				logTemplateIds.put(logID, templateId);
			}
			List<String> eventMessage = new ArrayList<>();
			eventMessage.add(templateId);
			eventMessage.add(templateStr);
			eventMessage.add(Integer.toString(occurrence));
			eventMessages.add(eventMessage);			
		}
		
		
		File parseredFile = new File(outDir + "/" + logName + "_parsered.csv");
		File templateFile = new File(outDir + "/" + logName + "_templates.csv");
		try {
			 BufferedWriter bufferedWriter = new BufferedWriter(new FileWriter(parseredFile));
			 bufferedWriter.write("logID,template,templateID");
			 bufferedWriter.newLine();
			 for(int i=1;i<=logTemplates.size();i++) {
				 bufferedWriter.write(i+","+logTemplates.get(i)+","+logTemplateIds.get(i));
				 bufferedWriter.newLine();
			 }
			 bufferedWriter.close();
		} catch(FileNotFoundException ex) {
            System.out.println("File not found！");
        } catch (IOException ex) {
            System.out.println("Error！");
        }
		
		try {
			 BufferedWriter bufferedWriter = new BufferedWriter(new FileWriter(templateFile));
			 bufferedWriter.write("templateID,template,occurrence");
			 bufferedWriter.newLine();
			 for(int i=0;i<eventMessages.size();i++) {
				 bufferedWriter.write(eventMessages.get(i).get(0)+","+eventMessages.get(i).get(1) +
						 "," + eventMessages.get(i).get(2));
				 bufferedWriter.newLine();
			 }
			 bufferedWriter.close();
		} catch(FileNotFoundException ex) {
           System.out.println("File not found！");
       } catch (IOException ex) {
           System.out.println("Error！");
       }
		
	}
	

	
	public String listToStr(List<String> listStr) {
		String str = "";
		for(int i=0;i<listStr.size();i++) {
			str += listStr.get(i);
			if(i!=listStr.size()-1) {
				str += " ";
			}
		}
		return str;
	}
	
	public boolean compareStrArray(List<String> seq1,List<String> seq2) {
		for(int i=0;i<seq1.size();i++) {
			if(!seq1.get(i).equals(seq2.get(i))) {
				return false;
			}
		}
		return true;
	}
	
	public List<String> getTemplate(List<String> seq1,List<String> seq2) {
		assert seq1.size() == seq2.size();
		
		List<String> retVal = new ArrayList<>();
		for(int i=0;i<seq1.size();i++) {
			if(seq1.get(i).equals(seq2.get(i))) {
				retVal.add(seq1.get(i));
			}
			else {
				retVal.add("<*>");
			}
		}
		return retVal;
	}
	public void addSeqToPrefixTree(Node rn,Logcluster logClust) {
		Node firstLayerNode = new Node();
		String seqLen = Integer.toString(logClust.logTemplate.size());
		if(!rn.childD.containsKey(seqLen)) {
			firstLayerNode.setDepth(1);
			firstLayerNode.setDigit(logClust.logTemplate.size());
			rn.addChildNode(seqLen, firstLayerNode);
		}
		else {
			firstLayerNode = rn.childD.get(seqLen);
		}
		Node parentN = firstLayerNode;
		int currentDepth = 1;
		for(int i=0;i<logClust.logTemplate.size();i++) {
			if(currentDepth >= depth || currentDepth > logClust.logTemplate.size()) {
				parentN.addChildClu(logClust);
				break;
			}
			if(!parentN.childD.containsKey(logClust.logTemplate.get(i))) {
				if(!isNumeric(logClust.logTemplate.get(i))) {
					if(parentN.childD.containsKey("<*>")) {
						if(parentN.childD.size() < maxChild) {
							Node newNode = new Node();
							newNode.setDepth(currentDepth+1);
							newNode.setToken(logClust.logTemplate.get(i));
							parentN.addChildNode(logClust.logTemplate.get(i),newNode);
							parentN = newNode;
						}
						else{
							parentN = parentN.childD.get("<*>");
						}
					}
					else {
						if(parentN.childD.size()+1 < maxChild) {
							Node newNode = new Node();
							newNode.setDepth(currentDepth+1);
							newNode.setToken(logClust.logTemplate.get(i));
							parentN.addChildNode(logClust.logTemplate.get(i),newNode);
							parentN = newNode;
						}
						else if(parentN.childD.size()+1 == maxChild) {
							Node newNode = new Node();
							newNode.setDepth(currentDepth+1);
							newNode.setToken("<*>");
							parentN.addChildNode("<*>",newNode);
							parentN = newNode;
						}
						else{
							parentN = parentN.childD.get("<*>");
						}
					}
				}
				else {
					if(!parentN.childD.containsKey("<*>")) {
						Node newNode = new Node();
						newNode.setDepth(currentDepth+1);
						newNode.setToken("<*>");
						parentN.addChildNode("<*>",newNode);
						parentN = newNode;
					}
					else {
						parentN = parentN.childD.get("<*>");
					}
					
				}
			}
			else {
				parentN = parentN.childD.get(logClust.logTemplate.get(i));
			}
			currentDepth+=1;
		}

		
	}
	
	public Logcluster treeSearch(Node rn,List<String> seq) {
		Logcluster retLogClust = new Logcluster();
		String seqLen = Integer.toString(seq.size());
		if (!rn.childD.containsKey(seqLen)) {
			return retLogClust;
		}
		Node parentN = rn.childD.get(seqLen);
		int currentDepth = 1;
		for(int i=0;i<seq.size();i++) {
			if(currentDepth>=depth || currentDepth>seq.size()) {
				break;
			}
			if(parentN.childD.containsKey(seq.get(i))) {
				parentN = parentN.childD.get(seq.get(i));
			}
			else if(parentN.childD.containsKey("<*>")) {
				parentN = parentN.childD.get("<*>");
			}
			else {
				return retLogClust;
			}
			currentDepth += 1;
		}
		
		List<Logcluster> logClustL = parentN.childClu;
		retLogClust = fastMatch(logClustL,seq);
		return retLogClust;
	}
	
	public Result seqDist(List<String> seq1,List<String> seq2){
		assert seq1.size() == seq2.size();
		
		double simTokens = 0;
		int numOfPar = 0;
		double retVal;
		
		for(int i=0;i<seq1.size();i++) {
			if(seq1.get(i).equals("<*>")) {
				numOfPar +=1;
				continue;
			}
			if(seq1.get(i).equals(seq2.get(i))) {
				simTokens+=1;
			}
		}
		retVal = simTokens/seq1.size();
		Result result = new Result(numOfPar,retVal);
			
		return result;
	}
	
	public Logcluster fastMatch(List<Logcluster> logClustL,List<String> seq) {
		Logcluster retLogClust = new Logcluster();
		double maxSim = -1;
		double curSim;
		int maxNumOfPara = -1;
		int curNumOfPara;
		Logcluster maxClust = new Logcluster();
		
		for(int i=0;i<logClustL.size();i++) {
			Result res = seqDist(logClustL.get(i).logTemplate,seq);
			curSim = res.retVal;
			curNumOfPara = res.numOfPar;
			if(curSim>maxSim || (curSim==maxSim && curNumOfPara > maxNumOfPara)) {
				maxSim = curSim;
				maxNumOfPara = curNumOfPara;
				maxClust = logClustL.get(i);
			}
		}
		if(maxSim >= St) {
			retLogClust = maxClust;
		}
		
		return retLogClust;
	}
	
	
	public String preprocess(String line) {
		for(int i=0;i<rex.size();i++) {
			line = line.replaceAll(rex.get(i), "<*>");
		}
		
		return line;
	}
	
	public String generateLogformatRegex() {
		List<String> splitters = new ArrayList<>();
		String regex = "";
		Pattern pattern = Pattern.compile("(<([^<>]+)>)|([^<>]+)");
        Matcher matcher = pattern.matcher(logFormat);
        while (matcher.find()) {
    	    		splitters.add(matcher.group(0));
        }
        headers.add("lineId");
        for(int i=0;i<splitters.size();i++) {
	    		if(i%2!=0) {
	    			String splitter = splitters.get(i).replaceAll(" +","\\\\s+");
	    			regex += splitter;
	    		}
	    		else {
	    			String header = splitters.get(i).split("<|>")[1];
	    			headers.add(header);
	    			regex += "(?<" + header + ">.*?)";
	    		}
	    }
        return regex;
	}
	
	public void loadData() {
		String regex = generateLogformatRegex();
        int lineCount = 0;
        Pattern pattern = Pattern.compile(regex);
        try {
	        FileReader fileReader = new FileReader(inDir+"/"+logName);
	        BufferedReader bufferedReader = new BufferedReader(fileReader);
	        String line = null;
	        while ((line = bufferedReader.readLine()) != null) {
	        		Matcher matcher = pattern.matcher(line); 
	    			
	    			if(matcher.matches()) {
	    				List<String> message = new ArrayList<>();
	    				message.add(Integer.toString(lineCount+1));
	        			for(int i=1;i<headers.size();i++) {
	        				message.add(matcher.group(headers.get(i)));
	        			}
	        			logMessages.add(message);
	        			
	    			}
	    			else {
	    				System.out.println("Line:"+lineCount + "Mistake regex.");
	    			}
	    			
	    			lineCount+=1;
	   		}
	        
	        bufferedReader.close();
	        fileReader.close();
        } catch(FileNotFoundException ex) {
            System.out.println("File not found!");
        } catch (IOException ex) {
            System.out.println("Error!");
        }
        
        try {
        		FileWriter fileWriter= new FileWriter(outDir+"/"+logName + "_structured.csv");
        		BufferedWriter bufferedWriter= new BufferedWriter(fileWriter);
        		for(int i=0;i<headers.size();i++) {
        			bufferedWriter.write(headers.get(i));
        			if(i!=headers.size()-1) {
        				bufferedWriter.write(",");
        			}
        		}
        		bufferedWriter.newLine();
        		for(int i=0;i<logMessages.size();i++) {
        			for(int j=0;j<headers.size();j++) {
            			bufferedWriter.write(logMessages.get(i).get(j));
            			if(j!=headers.size()-1) {
            				bufferedWriter.write(",");
            			}
            		}
        			bufferedWriter.newLine();
        		}
        		bufferedWriter.close();
        		fileWriter.close();
        		
        } catch(FileNotFoundException ex) {
            System.out.println("File not found!");
        } catch (IOException ex) {
            System.out.println("Error!");
        }
        
	}

	
	public void loadTree() {
		File file = new File(treeFile);
		if(file.exists()) {
			try {
				ObjectInputStream ois=new ObjectInputStream(new FileInputStream(treeFile));
				rootNode = (Node) ois.readObject();
				System.out.println(rootNode.childD);
				ois.close();
				}catch(FileNotFoundException e) {
					e.printStackTrace();
				}catch(IOException e) {
					e.printStackTrace(); 
				}catch(ClassNotFoundException e) {
					e.printStackTrace();
				}
		}
		String onlineRegex = generateLogformatRegex();
		parsePattern = Pattern.compile(onlineRegex);	
	}
    
}