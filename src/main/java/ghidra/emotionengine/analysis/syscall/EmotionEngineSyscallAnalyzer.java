package ghidra.emotionengine.analysis.syscall;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.emotionengine.EmotionEngineLoader;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.ExternalManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.bytesearch.*;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

public final class EmotionEngineSyscallAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "Syscall Analyzer";
	private static final String DESCRIPTION =
		"Locates syscalls and applies the appropriate call fixup and function signature";

	public EmotionEngineSyscallAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
	}

	@Override
	public boolean canAnalyze(Program program) {
		return EmotionEngineLoader.canLoad(program);
	}

	@Override
	public boolean getDefaultEnablement(Program program) {
		return canAnalyze(program);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		createBios(program);
		SyscallMatchAction action = new SyscallMatchAction(log);
		MemoryBytePatternSearcher searcher = new MemoryBytePatternSearcher("Syscall Searcher");
		searcher.addPattern(action.getPattern());
		searcher.search(program, set, monitor);
		return true;
	}

	private static void createBios(Program program) {
		ExternalManager manager = program.getExternalManager();
		Library lib = manager.getExternalLibrary(SyscallMatchAction.BIOS);
		if (lib == null) {
			try {
				manager.addExternalLibraryName(SyscallMatchAction.BIOS, SourceType.IMPORTED);
			} catch (DuplicateNameException | InvalidInputException e) {
				// can't happen
				throw new AssertException(e);
			}
		}
	}
}
