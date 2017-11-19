import java.io.FileReader;
import java.util.ArrayList;
import java.util.Iterator;

//import org.json.*;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

public class Analyser{
	
	private static ArrayList<Pattern> patterns = new ArrayList<Pattern>();
	private static ArrayList<Threat> threats = new ArrayList<Threat>();
	
	public static void main(String args[]){
		
		String filename=null;
		System.out.println(args.length);
		if(args.length<1){
			System.out.println("Please specify a file");
			System.exit(1);
		}else{
			filename=args[0];
			System.out.println(filename);
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
		
		//parse slice
		//load threats
		jsonObject =  (JSONObject) obj;
		checkEntryPoints(filename, jsonObject);
		
		
		
		
		//list threats
		//parse threats
		System.out.println("The following variables were identified as threats");
		for(Threat t: threats){
			System.out.println(t.getName());
			checkVulnerability(t,filename, jsonObject);
			checkSink(t, filename, jsonObject);
			
		}

		//TODO mark variable as sanitized or not
		
		//TODO check if variable is assigned to another variable, if it is, replace names? (u->q)?
		
		//TODO check if variable is used in sink
			//if it is, check if it's sanitized
				//if not, print vulnerability
		
		System.out.println("Analysis done");
	}

	private static void checkVulnerability(Threat t,String filename, JSONObject jsonObject) {
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
	        	        	
        		//assignment to another variable
        		if(kind.equals("encapsed")){
        			JSONArray values = (JSONArray) jsobj.get("value");
        			Iterator<JSONObject> iterator2 = values.iterator();
        			while(iterator2.hasNext()){
        				
        				jsobj2=iterator2.next();	
        				
        				if(jsobj2.containsKey("kind") && jsobj2.containsKey("name")){	
	        				kindtmp = (String) jsobj2.get("kind");
	        				nametmp = (String) jsobj2.get("name");
	        				if(kindtmp.equals("variable") && nametmp.equals(t.getName())){
	        					//get left side
	        					jsobj2 = (JSONObject) jsonObject.get("left");				
	        					Threat tmp = new Threat((String)jsobj2.get("name"), t.getType(),t.isSanitized(), false);
	        					//threats.add(tmp);
	        					System.out.println("it gets here");
	        				}
        				}				
        			}
        		}
        		
        		
        		//jsobj2 = (JSONObject) jsobj.get("kind");
        		
        		
        		
        	}
        	
        	
        	//check if the threat t is being used on a sensitive sink
        }
	}

	private static void checkEntryPoints(String filename, JSONObject jsonObject) {
            
        String name;
        
        JSONArray children = (JSONArray) jsonObject.get("children");
        
        Iterator<JSONObject> iterator = children.iterator();
        while (iterator.hasNext()) {
        	
        	jsonObject = iterator.next();
        	name = (String) jsonObject.get("kind");
        	
        	if(name.equals("assign")){
        		//check right for entry points
        		JSONObject jsobj = (JSONObject) jsonObject.get("right");
        		name = (String) jsobj.get("kind");
        		if(name.equals("offsetlookup")){
        			
            		JSONObject jsobj2 = (JSONObject) jsobj.get("what");
            		if((jsobj2).containsKey("name")){
  
            			//check for entry points - assignments with entry points from patterns 
            			for(Pattern p : patterns){
            				
            				if(p.getEntrypoints().contains(jsobj2.get("name"))){
   
	            				//check left for variable name
	            				jsobj = (JSONObject) jsonObject.get("left");
	            				Threat t = new Threat((String) jsobj.get("name"), p.getName() ,false, false);
	            				threats.add(t);
	            				break;
            				}
            			}
            		}
        		}
        	}       	
        }		
	}
	
	private static void checkSink(Threat t,String filename, JSONObject jsonObject){
		JSONArray children = (JSONArray) jsonObject.get("children");
		
		Iterator<JSONObject> iterator = children.iterator();
		
		while(iterator.hasNext()){
			jsonObject = iterator.next();
			String name = (String) jsonObject.get("kind");
			
			if(name.equals("assign")){
				//check right for call functions
				JSONObject jsobj = (JSONObject) jsonObject.get("right");
				name = (String) jsobj.get("kind");
				if(name.equals("call")){
					JSONObject jsobj2 = (JSONObject) jsobj.get("what");
					
					if((jsobj2).containsKey("name")){
						//check if threat is in list of sinks of patterns
						for(Pattern p : patterns){
							
							if(p.getSinks().contains(jsobj2.get("name"))){
								// check if threat is an argument of sink
								JSONArray arguments = (JSONArray) jsobj.get("arguments");
								for(Object o : arguments){
									JSONObject arg = (JSONObject) o;
									String nameArg = (String) arg.get("name");
									
									if(nameArg.equals(t.getName())){
										System.out.println("Threat is sink");
									}
								}
							}
						}
					}
					
					
				}
				
			}
			
			
		}
		
	}
	
}
