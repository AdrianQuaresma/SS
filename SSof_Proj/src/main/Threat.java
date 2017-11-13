public class Threat {
	
	private String _name;
	private boolean _sanitized;
	private boolean _sink;
	
	public Threat(String name, boolean sanitized, boolean sink){
		_name=name;
		_sanitized=sanitized;
		_sink=sink;
	}

	public String getName() {
		return _name;
	}

	public void setName(String _name) {
		this._name = _name;
	}
	
	public void setSanitized() {
		this._sanitized = true;
	}
	
	public void setSink() {
		this._sink = true;
	}
	
	public boolean isThreat(){
		return _sink && !_sanitized;
	}
}
