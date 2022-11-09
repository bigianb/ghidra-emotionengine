package ghidra.app.util.demangler;

public abstract class UserDemangledObject extends DemangledObject {

	protected UserDemangledObject(String mangled, String originalDemangled) {
		super(mangled, originalDemangled);
	}

}
