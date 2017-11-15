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
		System.out.println("The following variables were identified as threats");
		for(Threat t: threats){
			
			System.out.println(t.getName());
			
			//TODO mark variable as sanitized or not
		}
		
		//TODO check if variable is assigned to another variable, if it is, replace names? (u->q)?
		
		//TODO check if variable is used in sink
			//if it is, check if it's sanitized
				//if not, print vulnerability
		
		System.out.println("Analysis done");
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
        		name = (String) jsonObject.get("kind");
        		if((jsobj).containsKey("what")){
        			
            		JSONObject jsobj2 = (JSONObject) jsobj.get("what");
            		if((jsobj2).containsKey("name")){
            			
            			//check for entry points - assignments with entry points from patterns 
            			for(Pattern p : patterns){
            				
            				if(p.getEntrypoints().contains(jsobj2.get("name"))){
	            				//check left for variable name
	            				jsobj = (JSONObject) jsonObject.get("left");
	            				Threat t = new Threat((String) jsobj.get("name"), false, false);
	            				threats.add(t);
	            				break;
            				}
            			}
            		}
        		}
        	}       	
        }		
	}
	
	
}