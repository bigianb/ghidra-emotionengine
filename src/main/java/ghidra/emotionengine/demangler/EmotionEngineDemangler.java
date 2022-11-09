package ghidra.emotionengine.demangler;

import ghidra.app.util.demangler.*;
import ghidra.app.util.demangler.gnu.GnuDemangler;
import ghidra.app.util.demangler.gnu.GnuDemanglerFormat;
import ghidra.app.util.demangler.gnu.GnuDemanglerOptions;
import ghidra.program.model.listing.Program;

public final class EmotionEngineDemangler {

	private final Demangler demangler;
	private final DemanglerOptions options;

	public static EmotionEngineDemangler getDemangler(Program program) {
		if (MetrowerksDemangler.isMetrowerksProgram(program)) {
			return new EmotionEngineDemangler(new MetrowerksDemangler());
		}
		return new EmotionEngineDemangler(new GnuDemangler());
	}

	private EmotionEngineDemangler(GnuDemangler demangler) {
		this(demangler, new GnuDemanglerOptions(GnuDemanglerFormat.AUTO, true));
	}

	private EmotionEngineDemangler(MetrowerksDemangler demangler) {
		this(demangler, new DemanglerOptions());
	}

	private EmotionEngineDemangler(Demangler demangler, DemanglerOptions options) {
		this.demangler = demangler;
		this.options = options;
		options.setDemangleOnlyKnownPatterns(false);
	}

	public Demangler getDemangler() {
		return demangler;
	}

	public DemanglerOptions getOptions() {
		return options;
	}

	public DemangledObject demangle(String mangled) {
		try {
			return demangler.demangle(mangled, options);
		} catch (DemangledException e) {
			return null;
		}
	}

}
