package ghidra.emotionengine.elf;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.scalar.Scalar;

public abstract class AbstractElfHeaderData {

	public static final String STRING_TABLE_NAME = ".strtab";
	public static final String SYMBOL_TABLE_NAME = ".symtab";
	public static final String SECTION_HEADER_NAME_TABLE = ".shstrtab";
	public static final String SECTION_HEADERS_NAME = "_elfSectionHeaders";

	protected final Data data;

	protected AbstractElfHeaderData(Data data) {
		this.data = data;
	}

	@Override
	public final boolean equals(Object o) {
		if (o == null || !(o instanceof AbstractElfHeaderData)) {
			return false;
		}
		return data.equals(((AbstractElfHeaderData) o).data);
	}

	public Program getProgram() {
		return data.getProgram();
	}

	protected MemoryBlock getBlock(String name) {
		return getProgram().getMemory().getBlock(name);
	}

	protected Address getAddress(MemoryBlock block, long addr) {
		AddressSpace space = block.getStart().getAddressSpace();
		if (!space.isLoadedMemorySpace()) {
			return block.getStart().add(addr);
		}
		return space.getAddress(addr);
	}

	protected Data getData(Address address) {
		return getProgram().getListing().getDataAt(address);
	}

	protected ElfStringTable getStringTable() {
		return new ElfStringTable(getProgram(), getBlock(STRING_TABLE_NAME));
	}

	protected ElfStringTable getSectionStringTable() {
		return new ElfStringTable(getProgram(), getBlock(SECTION_HEADER_NAME_TABLE));
	}

	protected ElfSymbolTableData getSymbolTable() {
		return new ElfSymbolTableData(getData(getBlock(SYMBOL_TABLE_NAME).getStart()));
	}

	protected ElfSectionData getSection(int index) {
		Data d = getData(getBlock(SECTION_HEADERS_NAME).getStart());
		ElfSectionTableData table = new ElfSectionTableData(d);
		return table.getSection(index);
	}

	protected Scalar getValue(int index) {
		return (Scalar) data.getComponent(index).getValue();
	}
}
