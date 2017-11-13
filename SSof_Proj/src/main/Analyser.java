import java.io.FileReader;
import java.util.ArrayList;
import java.util.Iterator;

//import org.json.*;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

public class Analyser{
	
	private static ArrayList<Pattern> patterns;
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
		
		//load patterns
		
		//parse slice
		
		checkEntryPoints(filename);
		
		//load threats
		
		//list threats
		
		for(Threat t: threats){
			System.out.println(t.getName());
		}
		
		//check for entry points - assignments with entry points from patterns 
		
		
		System.out.println("Analysis done");
	}

	private static void checkEntryPoints(String filename) {
		JSONParser parser = new JSONParser();
		 
        try {
 
            Object obj = parser.parse(new FileReader(
                    "src/resources/" + filename));
 
            JSONObject jsonObject =  (JSONObject) obj;
            
            String name;
            
            JSONArray children = (JSONArray) jsonObject.get("children");
            
            Iterator<JSONObject> iterator = children.iterator();
            while (iterator.hasNext()) {
            	jsonObject = iterator.next();
            	name = (String) jsonObject.get("kind");
            	System.out.println(name);
            	
            	if(name.equals("assign")){
            		//check right for entry points
            		JSONObject jsobj = (JSONObject) jsonObject.get("right");
            		name = (String) jsonObject.get("kind");
            		if((jsobj).containsKey("what")){
            			
	            		JSONObject jsobj2 = (JSONObject) jsobj.get("what");
	            		if((jsobj2).containsKey("name")){
	         			
	            			if(jsobj2.get("name").equals("_GET")){
	            				System.out.println("bue fixe");
	            				
	            				//check left for variable name
	            				jsobj = (JSONObject) jsonObject.get("left");
	            				Threat t = new Threat((String) jsobj.get("name"), false, false);
	            				threats.add(t);
	            				
	            			}
	            		}
            		}
                    
            	}       	
               // System.out.println(jsonObject);
            }
            
            
        }catch (Exception e) {
            e.printStackTrace();
        }
		
	}
	
	
}