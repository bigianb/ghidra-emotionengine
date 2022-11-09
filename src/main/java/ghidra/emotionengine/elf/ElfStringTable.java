package ghidra.emotionengine.elf;

import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;

public final class ElfStringTable {

	private final Program program;
	private final MemoryBlock block;

	ElfStringTable(Program program, MemoryBlock block) {
		this.program = program;
		this.block = block;
	}

	protected String getValue(long index) {
		Listing listing = program.getListing();
		Data data = listing.getDataAt(block.getStart().add(index));
		return data == null || data.getValueClass() != String.class ?
			"" : (String) data.getValue();
	}

}
