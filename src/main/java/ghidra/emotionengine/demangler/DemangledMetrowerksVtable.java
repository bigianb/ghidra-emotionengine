package ghidra.emotionengine.demangler;

import ghidra.app.util.demangler.DemangledDataType;

final class DemangledMetrowerksVtable extends DemangledMetrowerksSpecial {

	public DemangledMetrowerksVtable(String mangled, DemangledDataType type) {
		super(mangled, "vtable", type);
	}
}
