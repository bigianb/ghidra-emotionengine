package ghidra.emotionengine.elf;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Data;
import ghidra.program.model.mem.MemoryBlock;

@SuppressWarnings("unused")
public final class ElfSymbolData extends AbstractElfHeaderData {

	private static final int NAME_ORDINAL = 0;
	private static final int VALUE_ORDINAL = 1;
	private static final int SIZE_ORDINAL = 2;
	private static final int INFO_ORDINAL = 3;
	private static final int OTHER_ORDINAL = 4;
	private static final int SHNDX_ORDINAL = 5;

	/* Legal values for ST_BIND subfield of st_info (symbol binding).  */

	private static final int STB_LOCAL = 0;		/* Local symbol */
	private static final int STB_GLOBAL = 1;		/* Global symbol */
	private static final int STB_WEAK = 2;		/* Weak symbol */
	private static final int STB_NUM = 3;		/* Number of defined types.  */
	private static final int STB_LOOS = 10;		/* Start of OS-specific */
	private static final int STB_GNU_UNIQUE = 10;		/* Unique symbol.  */
	private static final int STB_HIOS = 12;		/* End of OS-specific */
	private static final int STB_LOPROC = 13;		/* Start of processor-specific */
	private static final int STB_HIPROC = 15;		/* End of processor-specific */

	/* Legal values for ST_TYPE subfield of st_info (symbol type).  */

	private static final int STT_NOTYPE = 0;		/* Symbol type is unspecified */
	private static final int STT_OBJECT = 1;		/* Symbol is a data object */
	private static final int STT_FUNC = 2;		/* Symbol is a code object */
	private static final int STT_SECTION = 3;		/* Symbol associated with a section */
	private static final int STT_FILE = 4;		/* Symbol's name is file name */
	private static final int STT_COMMON = 5;		/* Symbol is a common data object */
	private static final int STT_TLS = 6;		/* Symbol is thread-local data object*/
	private static final int STT_NUM = 7;		/* Number of defined types.  */
	private static final int STT_LOOS = 10;		/* Start of OS-specific */
	private static final int STT_GNU_IFUNC = 10;		/* Symbol is indirect code object */
	private static final int STT_HIOS = 12;		/* End of OS-specific */
	private static final int STT_LOPROC = 13;		/* Start of processor-specific */
	private static final int STT_HIPROC = 15;		/* End of processor-specific */

	public ElfSymbolData(Data data) {
		super(data);
	}

	private AddressSpace getSpace() {
		return getBlock().getStart().getAddressSpace();
	}

	public String getName() {
		long offset = getValue(NAME_ORDINAL).getValue();
		Address address = getAddress(getBlock(STRING_TABLE_NAME), offset);
		Data d = getData(address);
		return (String) d.getValue();
	}

	public Address getAddress() {
		long addr = getValue(VALUE_ORDINAL).getValue();
		return getSpace().getAddress(addr);
	}

	public long getSize() {
		return getValue(SIZE_ORDINAL).getValue();
	}

	public MemoryBlock getBlock() {
		ElfSectionData d = getSection((int) getValue(SHNDX_ORDINAL).getValue());
		return d.getBlock();
	}

	public ElfSectionData getSection() {
		return getSection(getSectionIndex());
	}

	public int getSectionIndex() {
		return (int) getValue(SHNDX_ORDINAL).getValue();
	}

	public long getInfo() {
		return getValue(INFO_ORDINAL).getValue();
	}

	public long getOther() {
		return getValue(OTHER_ORDINAL).getValue();
	}

	public long getBind() {
		return getInfo() >> 4;
	}

	public long getType() {
		return getInfo() & 0xf;
	}

	public boolean isLocal() {
		return getBind() == STB_LOCAL;
	}

	public boolean isGlobal() {
		return getBind() == STB_GLOBAL;
	}

	public boolean isWeak() {
		return getBind() == STB_WEAK;
	}

	public boolean isNum() {
		return getBind() == STB_NUM;
	}

	public boolean isFunction() {
		return getType() == STT_FUNC;
	}

	public boolean isObject() {
		return getType() == STT_OBJECT;
	}

}
