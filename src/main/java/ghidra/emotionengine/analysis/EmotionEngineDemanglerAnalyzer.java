package ghidra.emotionengine.analysis;

import ghidra.app.plugin.core.analysis.AbstractDemanglerAnalyzer;
import ghidra.app.util.demangler.*;
import ghidra.app.util.demangler.gnu.GnuDemangler;
import ghidra.app.util.demangler.gnu.GnuDemanglerFormat;
import ghidra.app.util.demangler.gnu.GnuDemanglerOptions;
import ghidra.app.util.importer.MessageLog;
import ghidra.emotionengine.EmotionEngineLoader;
import ghidra.emotionengine.demangler.MetrowerksDemangler;
import ghidra.framework.options.Options;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;
import ghidra.util.classfinder.ExtensionPointProperties;

@ExtensionPointProperties(priority = 2)
public class EmotionEngineDemanglerAnalyzer extends AbstractDemanglerAnalyzer {

	private static final String NAME = EmotionEngineDemanglerAnalyzer.class.getSimpleName();
	private static final String DESCRIPTION =
		"Demangler analyzer specialized for the Emotion Engine";

	private static final String OPTION_NAME_APPLY_SIGNATURE = "Apply Function Signatures";
	private static final String OPTION_DESCRIPTION_APPLY_SIGNATURE =
		"Apply any recovered function signature, in addition to the function name";

	private Demangler demangler;
	private boolean doSignatureEnabled = true;

	public EmotionEngineDemanglerAnalyzer() {
		super(NAME, DESCRIPTION);
		setDefaultEnablement(true);
	}

	@Override
	public boolean canAnalyze(Program program) {
		return EmotionEngineLoader.canLoad(program);
	}

	@Override
	public void registerOptions(Options options, Program program) {

		HelpLocation help = new HelpLocation("AutoAnalysisPlugin", "Demangler_Analyzer");
		options.registerOption(OPTION_NAME_APPLY_SIGNATURE, doSignatureEnabled, help,
			OPTION_DESCRIPTION_APPLY_SIGNATURE);
		setDemangler(program);
	}

	@Override
	public void optionsChanged(Options options, Program program) {
		doSignatureEnabled = options.getBoolean(OPTION_NAME_APPLY_SIGNATURE, doSignatureEnabled);
		setDemangler(program);
	}

	@Override
	protected DemanglerOptions getOptions() {

		GnuDemanglerOptions options = new GnuDemanglerOptions(GnuDemanglerFormat.AUTO, true);
		options.setDoDisassembly(true);
		options.setApplySignature(doSignatureEnabled);
		options.setDemangleOnlyKnownPatterns(false);
		return options;
	}

	@Override
	protected DemangledObject doDemangle(String mangled, DemanglerOptions options, MessageLog log)
			throws DemangledException {
		return demangler.demangle(mangled, options);
	}

	private void setDemangler(Program program) {
		if (MetrowerksDemangler.isMetrowerksProgram(program)) {
			this.demangler = new MetrowerksDemangler();
		} else {
			this.demangler = new GnuDemangler();
		}
	}

}
