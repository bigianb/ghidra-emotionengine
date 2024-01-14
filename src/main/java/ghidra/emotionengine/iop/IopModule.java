package ghidra.emotionengine.iop;

import java.util.*;

import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

public final class IopModule {

	private final String name;
	private final Map<Integer, String> functions;
	
	IopModule(XmlPullParser parser) {
		XmlElement element = parser.next();
		this.name = element.getAttribute("name");
		functions = new TreeMap<>();
		while (parser.hasNext() && parser.peek().getName().equals("entry")) {
			element = parser.next();
			int ordinal = Integer.parseInt(element.getAttribute("ordinal"));
			functions.put(ordinal, element.getAttribute("name"));
			parser.next();
		}
	}

	public String getName() {
		return name;
	}
	
	public String getFunction(int ordinal) {
		return functions.get(ordinal);
	}
	
	public boolean containsKey(int ordinal) {
		return functions.containsKey(ordinal);
	}
	
	public Collection<String> getFunctions() {
		return functions.values();
	}
}
