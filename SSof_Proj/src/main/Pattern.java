import java.util.ArrayList;

public class Pattern {
	
	private String _name;
	private ArrayList<String> _entrypoints;
	private ArrayList<String> _validations;
	private ArrayList<String> _sinks;
	
	
	public Pattern(String name, ArrayList<String> entrypoints, 
			ArrayList<String> validations,ArrayList<String> sinks){
		
		setName(name);
		setEntrypoints(entrypoints);
		setValidations(validations);
		setSinks(sinks);
	}


	public String getName() {
		return _name;
	}


	public void setName(String _name) {
		this._name = _name;
	}


	public ArrayList<String> getEntrypoints() {
		return _entrypoints;
	}


	public void setEntrypoints(ArrayList<String> _entrypoints) {
		this._entrypoints = _entrypoints;
	}


	public ArrayList<String> getValidations() {
		return _validations;
	}


	public void setValidations(ArrayList<String> _validations) {
		this._validations = _validations;
	}


	public ArrayList<String> getSinks() {
		return _sinks;
	}


	public void setSinks(ArrayList<String> _sinks) {
		this._sinks = _sinks;
	}
	
}
