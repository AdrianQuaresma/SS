import java.io.FileReader;
import java.util.ArrayList;
import java.util.Iterator;

//import org.json.*;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

public class Analyser{
	
	private static ArrayList<Pattern> patterns = new ArrayList<Pattern>();
	private static ArrayList<Threat> entrypoints = new ArrayList<Threat>();
	private static ArrayList<Threat> threats = new ArrayList<Threat>();
	
	public static void main(String args[]){
		
		String filename=null;
		if(args.length<1){
			System.out.println("Please specify a file");
			System.exit(1);
		}else{
			filename=args[0];
			System.out.println("File Path is: src/resources/" + filename);
		}
		
		JSONObject jsonObject=null;
		Object obj = null;
		
		try{
			JSONParser parser = new JSONParser();
			obj = parser.parse(new FileReader("src/resources/" + filename));
	        
		}catch (Exception e){
			e.printStackTrace();
		}
		
		//load patterns
		PatternLoader loader = new PatternLoader();
		patterns = loader.loadPatterns();
		
		//parse slice for entry points
		jsonObject =  (JSONObject) obj;
		checkEntryPoints(filename, jsonObject);
		
		threats=new ArrayList<Threat>();
		
		ArrayList<Threat> array_aux = new ArrayList<Threat>();		

		
		System.out.println("Entrypoints: ");
		int i=1;
		//parse threats for new assignments
		for(Threat t: entrypoints){
			System.out.println(i + " - " + t.getName());
			array_aux = checkAssignment(t,filename, jsonObject);
			threats.addAll(array_aux);
			i++;
		}
		
		//parse threats for vulnerabilities
		for(Threat t: threats){
			checkVulnerability(t,filename, jsonObject);
			checkSink(t, filename, jsonObject);
			
		}
		System.out.println("Analysis done");
	}
	
	private static void checkEntryPoints(String filename, JSONObject jsonObject) {
        
        String kind;
        
        JSONArray children = (JSONArray) jsonObject.get("children");
        
        Iterator<JSONObject> iterator = children.iterator();
        while (iterator.hasNext()) {
        	
        	jsonObject = iterator.next();
        	kind = (String) jsonObject.get("kind");
        	
        	if(kind.equals("assign")){
        		//check right for entry points
        		JSONObject jsobj = (JSONObject) jsonObject.get("right");
        		kind = (String) jsobj.get("kind");
        		if(kind.equals("offsetlookup")){
        			
            		JSONObject jsobj2 = (JSONObject) jsobj.get("what");
            		if((jsobj2).containsKey("name")){
  
            			//check for entry points - assignments with entry points from patterns 
            			for(Pattern p : patterns){
            				
            				if(p.getEntrypoints().contains(jsobj2.get("name"))){
   
	            				//check left for variable name
	            				jsobj = (JSONObject) jsonObject.get("left");
	            				Threat t = new Threat((String) jsobj.get("name"), p.getName() ,false, false);
	            				entrypoints.add(t);
	            				break;
            				}
            			}
            		}
        		}
        	}
        	if(kind.equals("echo")){
        		JSONArray arguments = (JSONArray) jsonObject.get("arguments");
                
                Iterator<JSONObject> iterator2 = arguments.iterator();
                while (iterator2.hasNext()) {
                	JSONObject jsobj = iterator2.next();
                	if(jsobj.containsKey("what")){
                		JSONObject jsobj2 = (JSONObject) jsobj.get("what");
                		for(Pattern p : patterns){
            				
            				if(p.getEntrypoints().contains(jsobj2.get("name"))){
            					
	                			Threat tmp2 = new Threat((String)jsobj2.get("name"), "XSS",false, false);
	                			entrypoints.add(tmp2);
            					System.out.println("This slice is vulnerable to: Cross-Site Scripting");
            					break;
            				}
            			}
                	}
                }
        	}
        }		
	}

	private static void checkVulnerability(Threat t,String filename, JSONObject jsonObject) {
		String name, kind; 
        JSONArray children = (JSONArray) jsonObject.get("children");
        
        Iterator<JSONObject> iterator = children.iterator();
        while (iterator.hasNext()) {
        	
        	jsonObject = iterator.next();
        	name = (String) jsonObject.get("kind");
        	JSONObject jsobj, jsobj2;
        	
        	//check if the threat t was assigned to any other variable to be sanitized
        	if(name.equals("assign")){
        		
        		jsobj = (JSONObject) jsonObject.get("left");
        		if(jsobj.get("name").equals(t.getName())){
        			continue;
        		}
        		
        		jsobj = (JSONObject) jsonObject.get("right");       		
        		kind = (String) jsobj.get("kind");
        		
        		//check if the threat t is sanitized 
	        	if(kind.equals("call")){
	        		
	        		if(jsobj.containsKey("what") ){
	        			jsobj2 = (JSONObject) jsobj.get("what");
	        			
	        			for(Pattern p : patterns){
	        				if(p.getValidations().contains(jsobj2.get("name"))){
	        					t.setSanitizer((String)jsobj2.get("name"));
	        					t.setSanitized();
	        					break;
	        				}
	        			}
	        			
	        		}
        		}	    		
        	}
        }
	}

	private static ArrayList<Threat> checkAssignment(Threat t,String filename, JSONObject jsonObject) {
		
		ArrayList<Threat> threatstmp = new ArrayList<Threat>(entrypoints);
		
		String name, kind, kindtmp, nametmp; 
        JSONArray children = (JSONArray) jsonObject.get("children");
        
        Iterator<JSONObject> iterator = children.iterator();
        while (iterator.hasNext()) {
        	
        	jsonObject = iterator.next();
        	name = (String) jsonObject.get("kind");
        	JSONObject jsobj, jsobj2;
        	
        	//check if the threat t was assigned to any other variable, assign can also be a sanitization
        	if(name.equals("assign")){
        		
        		jsobj = (JSONObject) jsonObject.get("left");
        		name = (String)jsobj.get("name");
        		if(name.equals(t.getName())){
        			continue;
        		}
        		
        		jsobj = (JSONObject) jsonObject.get("right");       		
        		kind = (String) jsobj.get("kind");
        		
        		//check if the threat t is sanitized before it's assigned to another variable
	        	if(kind.equals("call")){
	        		
	        		if(jsobj.containsKey("what") ){
	        			jsobj2 = (JSONObject) jsobj.get("what");
	        			
	        			for(Pattern p : patterns){
	        				if(p.getValidations().contains(jsobj2.get("name"))){
	        					t.setSanitizer((String)jsobj2.get("name"));
	        					t.setSanitized();
	        					
	                			Threat tmp2 = new Threat(name, t.getType(),t.isSanitized(), false);
	        					
	                			threatstmp.add(tmp2);
	        					break;
	        				}
	        			}
	        			
	        		}
        		}
	        	if(kind.equals("bin")){	
	        		
	        		jsobj2 = (JSONObject) jsobj.get("right");
        			Threat tmp = new Threat((String)jsobj2.get("name"), t.getType(),t.isSanitized(), false);
  
	        		if(threatstmp.contains(tmp)){
	        			tmp.setName(name);
    					threatstmp.add(tmp);
	        		}
	        		
	        		jsobj2 = (JSONObject) jsobj.get("left");
        			Threat tmp2 = new Threat((String)jsobj2.get("name"), t.getType(),t.isSanitized(), false);
        			
	        		if(threatstmp.contains(tmp2)){
	        			tmp2.setName(name);
    					threatstmp.add(tmp2);
	        		}
	        		
	        		
	        	}
	        	        	
        		//assignment to another variable
        		if(kind.equals("encapsed")){
        			JSONArray values = (JSONArray) jsobj.get("value");
        			Iterator<JSONObject> iterator2 = values.iterator();
        			while(iterator2.hasNext()){
        				
        				jsobj2=iterator2.next();	
        				
        				if(jsobj2.containsKey("kind") && jsobj2.containsKey("name")){	
	        				kindtmp = (String) jsobj2.get("kind");
	        				nametmp = (String) jsobj2.get("name");
	        				
        					Threat tmp = new Threat(nametmp, t.getType(),t.isSanitized(), false);

	        				
	        				if(kindtmp.equals("variable") && threatstmp.contains(tmp)){
	        					//get left side
	        					jsobj2 = (JSONObject) jsonObject.get("left");				
	        					Threat tmp1 = new Threat((String)jsobj2.get("name"), t.getType(),t.isSanitized(), false);
	        					if(!threatstmp.contains(tmp1)){
	        						threatstmp.add(tmp1);
	        					}
	        					
	        				}
        				}				
        			}
        		}
        		    		
        	}
        	
        }
		return threatstmp;
	}
	
	
	
	
	private static void checkSink(Threat t,String filename, JSONObject jsonObject){
		JSONArray children = (JSONArray) jsonObject.get("children");
		
		Iterator<JSONObject> iterator = children.iterator();
		
		while(iterator.hasNext()){
			jsonObject = iterator.next();
			String name = (String) jsonObject.get("kind");
			JSONObject jsobj = (JSONObject) jsonObject.get("right");
			if(name.equals("assign")){

				//check right for call functions
				
				name = (String) jsobj.get("kind");
				if(name.equals("call") && jsobj.containsKey("what")){
					processCall(t, jsobj);
				}	
			}else if(name.equals("call") && jsonObject.containsKey("what")){
				processCall(t, jsonObject);
			}
			
			
		}
		
	}
	
	private static void processCall(Threat t, JSONObject jsonObject){
		JSONObject jsobj = (JSONObject) jsonObject.get("what");
		if((jsobj).containsKey("name")){
			//check if threat is in list of sinks of patterns
			for(Pattern p : patterns){
				
				if(p.getSinks().contains(jsobj.get("name"))){
					// check if threat is an argument of sink
					JSONArray arguments = (JSONArray) jsonObject.get("arguments");
					
					for(Object o : arguments){
						JSONObject arg = (JSONObject) o;
						String nameArg = (String) arg.get("name");
						
						if(nameArg.equals(t.getName())){
							
							if(!t.isSanitized()){
								System.out.println("This slice is vulnerable to: " + t.getType());
								break;
							}else{
								System.out.println("This slice is not vulnerable");
								System.out.println("The following function sanitizes data: " + t.getSanitizer());
								break;
							}
							
						}
					}
				}
			}
		}	
		
	}
	
}
