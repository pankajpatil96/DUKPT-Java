package dukpt.container;

import java.util.HashMap;

public class BDKContainer {
	private static BDKContainer instance;
	private HashMap<String,String> keyMap;
	
	private BDKContainer() { 
		keyMap = new HashMap<String, String>();
	}
	
	public static synchronized BDKContainer getInstance() {
		if(instance == null) {
			instance = new BDKContainer();
		}
		
		return instance;
	}
	
	public boolean insertBDK(String key, String BDK) {
		if(!keyMap.containsKey(key)) {
			keyMap. put(key, BDK);
			return true;
		}
		
		return false;
	}
	
	public String getBDK(String key) {
		if(keyMap.containsKey(key)) {
			return keyMap.get(key);
		}
		
		return null;
	}
	
	public void clear() {
		keyMap.clear();
	}
}