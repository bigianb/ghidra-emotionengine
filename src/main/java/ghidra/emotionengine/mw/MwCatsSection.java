package ghidra.emotionengine.mw;

import ghidra.app.util.bin.format.elf.ElfLoadHelper;
import ghidra.app.util.bin.format.elf.ElfSectionHeader;
import ghidra.emotionengine.EmotionEngineElfSection;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;

import static ghidra.emotionengine.EmotionEngineUtil.MW_PATH;

public class MwCatsSection implements EmotionEngineElfSection {
	
	private final ElfSectionHeader header;
	private final ElfLoadHelper elf;
	private static final DataType DATA_TYPE = buildDataType();
	
	public MwCatsSection(ElfSectionHeader header, ElfLoadHelper elf) {
		this.header = header;
		this.elf = elf;
	}

	@Override
	public void parse(TaskMonitor monitor) throws Exception {
		Program program = elf.getProgram();
		DataTypeManager dtm = program.getDataTypeManager();
		DataType dt = dtm.resolve(DATA_TYPE, DataTypeConflictHandler.KEEP_HANDLER);
		int count = (int)(header.getSize() / dt.getLength());
		ArrayDataType array = new ArrayDataType(dt, count, dt.getLength());
		Data data = elf.createData(elf.findLoadAddress(header, 0), array);
		ReferenceManager man = program.getReferenceManager();
		for (int i = 0; i < data.getNumComponents(); i++) {
			monitor.checkCanceled();
			Data comp = data.getComponent(i).getComponent(2);
			Scalar s = (Scalar) comp.getValue();
			Address addr = elf.getDefaultAddress(s.getUnsignedValue());
			man.addMemoryReference(comp.getAddress(), addr, RefType.DATA, SourceType.IMPORTED, 0);
		}
	}
	
	private static DataType buildDataType() {
		StructureDataType struct = new StructureDataType(MW_PATH, "MwCatsEntry", 0);
		struct.add(WordDataType.dataType, "version", null);
		struct.add(WordDataType.dataType, "size", null);
		struct.add(DWordDataType.dataType, "function", null);
		struct.setToMachineAligned();
		struct.setPackingEnabled(true);
		return struct;
	}
	
}
