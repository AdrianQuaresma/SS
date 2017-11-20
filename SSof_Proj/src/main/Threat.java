public class Threat {
	
	private String _name;
	private String _type;
	private String _sanitizer;
	private boolean _sanitized;
	private boolean _sink;
	
	public Threat(String name, String type, boolean sanitized, boolean sink){
		_name=name;
		_type=type;
		_sanitized=sanitized;
		_sink=sink;
	}

	public String getType() {
		return _type;
	}

	public void setType(String type) {
		this._type = type;
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
	
	public boolean isSanitized(){
		return _sanitized;
	}
	
	public boolean isThreat(){
		return _sink && !_sanitized;
	}

	public String getSanitizer() {
		return _sanitizer;
	}

	public void setSanitizer(String sanitizer) {
		this._sanitizer = sanitizer;
	}
	
	@Override
	public boolean equals(Object o){
		
		if(o instanceof Threat){
			Threat t = (Threat) o;
			return this.getName().equals(t.getName());
		}

		return false;
		
	}
}
