package ghidra.emotionengine.importer;

import java.io.InputStream;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.util.bin.ByteProvider;
import ghidra.emotionengine.elf.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

class MwOverlayLoaderHelper {

	private final MwOverlay overlay;
	private final Program program;
	private final TaskMonitor monitor;
	private final ElfSectionTableData sectionTable;
	private final ElfSymbolTableData symbolTable;

	MwOverlayLoaderHelper(ByteProvider provider, Program program,
			TaskMonitor monitor) {
		this.overlay = MwOverlay.get(provider);
		this.program = program;
		this.monitor = monitor;
		MemoryBlock block =
			program.getMemory().getBlock(AbstractElfHeaderData.SECTION_HEADERS_NAME);
		Data data = getListing().getDataAt(block.getStart());
		this.sectionTable = new ElfSectionTableData(data);
		block =
			program.getMemory().getBlock(AbstractElfHeaderData.SYMBOL_TABLE_NAME);
		data = getListing().getDataAt(block.getStart());
		this.symbolTable = new ElfSymbolTableData(data);
	}

	private Data createData(Address address, DataType dt) throws Exception {
		return getListing().createData(address, dt);
	}

	private Listing getListing() {
		return program.getListing();
	}

	private Memory getMemory() {
		return program.getMemory();
	}

	private SymbolTable getSymbolTable() {
		return program.getSymbolTable();
	}

	private Function createFunction(Address entry, String name) {
		CreateFunctionCmd cmd = new CreateFunctionCmd(name, entry, null, SourceType.IMPORTED);
		cmd.applyTo(program, monitor);
		return cmd.getFunction();
	}

	private void createLabel(Address address, String name) {
		SymbolTable table = getSymbolTable();
		try {
			table.createLabel(address, name, SourceType.IMPORTED);
		} catch (InvalidInputException e) {
			throw new AssertException(e);
		}
	}

	void loadOverlay()	throws Exception {
		Memory mem = getMemory();
		Listing listing = getListing();
		SymbolTable table = getSymbolTable();
		Address address = overlay.getAddress(program.getAddressFactory());
		String name = overlay.getName().replace(".bin", "");
		ElfSectionData section = sectionTable.getSection(name);
		try (InputStream is = overlay.getDataStream()) {
			MemoryBlock block = mem.createInitializedBlock(
				name, address, is, overlay.getSize(), monitor, true);
			block.setExecute(true);
			block.setRead(true);
			block.setWrite(true);
			createData(block.getStart(), MwOverlay.dataType);
			AddressSpace space = block.getStart().getAddressSpace();
			address = space.getAddress(overlay.getStaticInitStart());
			table.createLabel(address, "_static_init", SourceType.IMPORTED);
			Data data = listing.createData(address, getStaticInitializerTable(overlay));
			for (int i = 0; i < data.getNumComponents(); i++) {
				Data comp = data.getComponent(i);
				Address entry = (Address) comp.getValue();
				Function fun = createFunction(entry, null);
				fun.setReturnType(VoidDataType.dataType, SourceType.IMPORTED);
				fun.setCallingConvention(GenericCallingConvention.stdcall.getDeclarationName());
			}
			if (section != null) {
				symbolTable.getSymbolStream()
					.filter(s -> sectionTable.getSection(s.getSectionIndex()).equals(section))
					.forEach(this::applySymbol);
			}
		}
	}

	private void applySymbol(ElfSymbolData symbol) {
		if (symbol.isFunction()) {
			createFunction(symbol.getAddress(), symbol.getName());
		} else if (symbol.isObject() || symbol.isGlobal()) {
			createLabel(symbol.getAddress(), symbol.getName());
		}
	}

	private static DataType getStaticInitializerTable(MwOverlay overlay) {
		FunctionDefinition def = new FunctionDefinitionDataType(
			MwOverlay.getMwPath(), "mwStaticInitializer");
		def.setReturnType(VoidDataType.dataType);
		def.setGenericCallingConvention(GenericCallingConvention.stdcall);
		DataType pointer = new PointerDataType(def);
		int size = (overlay.getStaticInitEnd() - overlay.getStaticInitStart()) / 4;
		return new ArrayDataType(pointer, size, -1);
	}
}
