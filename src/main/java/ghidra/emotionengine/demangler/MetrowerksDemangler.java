package ghidra.emotionengine.demangler;

import ghidra.app.util.demangler.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.util.PropertyMapManager;
import ghidra.program.model.util.TypeMismatchException;
import ghidra.util.classfinder.ExtensionPointProperties;

@ExtensionPointProperties(priority = 2)
public class MetrowerksDemangler implements Demangler {

	public static final String METROWERKS_DEMANGLER_PROPERTY = "Metrowerks Demangler";

	@Override
	public boolean canDemangle(Program program) {
		return isMetrowerksProgram(program);
	}

	public static boolean isMetrowerksProgram(Program program) {
		try {
			PropertyMapManager manager = program.getUsrPropertyManager();
			return manager.getVoidPropertyMap(METROWERKS_DEMANGLER_PROPERTY) != null;
		} catch (TypeMismatchException e) {
			// not our property map
			return false;
		}
	}

	@Override
	public DemangledObject demangle(String mangled, boolean demangleOnlyKnownPatterns) {
		return MangledCodeWarriorSymbol.demangleSymbol(mangled);
	}

	@Override
	public DemangledObject demangle(String mangled, DemanglerOptions options) {
		return MangledCodeWarriorSymbol.demangleSymbol(mangled);
	}

}
