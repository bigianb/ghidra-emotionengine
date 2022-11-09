package ghidra.emotionengine.analysis;

import java.util.Arrays;
import java.util.List;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.emotionengine.EmotionEngineLoader;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.util.ProgramMemoryUtil;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public abstract class AbstractEmotionEngineAnalyzer extends AbstractAnalyzer {

	protected Program program;
	protected TaskMonitor monitor;
	protected MessageLog log;

	protected AbstractEmotionEngineAnalyzer(String name, String description, AnalyzerType type) {
		super(name, description, type);
	}

	@Override
	public boolean canAnalyze(Program program) {
		return EmotionEngineLoader.canLoad(program);
	}

	@Override
	public final boolean getDefaultEnablement(Program program) {
		return canAnalyze(program);
	}

	protected final void init(Program program, TaskMonitor monitor, MessageLog log) {
		this.program = program;
		this.monitor = monitor;
		this.log = log;
	}

	@Override
	public boolean removed(Program program, AddressSetView set, TaskMonitor monitor,
			MessageLog log) {
		this.program = null;
		this.monitor = null;
		this.log = null;
		// default result
		return false;
	}

	protected final List<Address> findStrings(String str) throws CancelledException {
		Memory mem = program.getMemory();
		List<MemoryBlock> blocks = Arrays.stream(mem.getBlocks())
			.filter(Predicate.not(MemoryBlock::isExecute))
			.filter(Predicate.not(MemoryBlock::isVolatile))
			.collect(Collectors.toList());
		return ProgramMemoryUtil.findString(".img", program, blocks, mem, monitor);
	}
}
