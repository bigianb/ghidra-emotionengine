package ghidra.emotionengine;

import java.util.Collections;
import java.util.Set;

import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.listing.Program;

public class EmotionEngineUtil {

	private static final String EE_PROCESSOR_NAME = "MIPS-R5900";
	private static final String IOP_PROCESSOR_NAME = "MIPS-R3000";
	public static final CategoryPath MW_PATH = new CategoryPath(CategoryPath.ROOT, "Metrowerks");
	private static final Set<String> TARGET_PROCESSORS = Collections.unmodifiableSet(
		Set.of(EE_PROCESSOR_NAME, IOP_PROCESSOR_NAME)
	);

	private EmotionEngineUtil() {}

	public static boolean isEmotionEngine(Program program) {
		return TARGET_PROCESSORS.contains(
			program.getLanguage().getProcessor().toString());
	}
}
