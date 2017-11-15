import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;

public class PatternLoader {

	public ArrayList<Pattern> loadPatterns(){
		
		Pattern p = null;
		ArrayList<Pattern> patterns = new ArrayList<Pattern>();
		
		String patName="";
		ArrayList<String> entries = new ArrayList<String>();
		ArrayList<String> san = new ArrayList<String>();
		ArrayList<String> sinks = new ArrayList<String>();
		
		try {
			File file = new File("src/resources/patterns.txt");
			FileReader fileReader = new FileReader(file);
			BufferedReader bufferedReader = new BufferedReader(fileReader);
			String line = bufferedReader.readLine();
			while ((line = bufferedReader.readLine()) != null) {			
				if(!line.equals(";")){
					patName=line;
					line = bufferedReader.readLine();
					entries=parseEntryPoints(line);
					line = bufferedReader.readLine();
					san=parseSanitizers(line);
					line = bufferedReader.readLine();
					sinks=parseSinks(line);
					p = new Pattern(patName, entries, san, sinks);
					patterns.add(p);			
				}
			}
			fileReader.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		return patterns;
		
	}
	
	public ArrayList<String> parseEntryPoints(String line){
		
		ArrayList<String> entries = new ArrayList<String>();
		String buffer[] = line.split(",");
		
		for(int i=0; i<buffer.length; i++){
			if(buffer[i].substring(0, 1).equals("$")){
				entries.add(buffer[i].substring(1));
			}else{
				entries.add(buffer[i]);
			}
		}
		
		return entries;
	}
	
	public ArrayList<String> parseSanitizers(String line){
		
		ArrayList<String> sanitizers = new ArrayList<String>();
		String buffer[] = line.split(",");
		
		for(int i=0; i<buffer.length; i++){
			sanitizers.add(buffer[i]);
		}
		
		return sanitizers;
		
	}
	public ArrayList<String> parseSinks(String line){
		
		ArrayList<String> sinks = new ArrayList<String>();
		String buffer[] = line.split(",");
		
		for(int i=0; i<buffer.length; i++){
			sinks.add(buffer[i]);
		}
		
		return sinks;
		
	}
	
}
