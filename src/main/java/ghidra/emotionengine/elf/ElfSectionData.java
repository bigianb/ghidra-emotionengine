package ghidra.emotionengine.elf;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Data;
import ghidra.program.model.mem.MemoryBlock;

public final class ElfSectionData extends AbstractElfHeaderData {

	private static final int NAME_ORDINAL = 0;
	private static final int TYPE_ORDINAL = 1;
	private static final int FLAGS_ORDINAL = 2;
	private static final int ADDR_ORDINAL = 3;
	private static final int OFFSET_ORDINAL = 4;
	private static final int SIZE_ORDINAL = 5;
	private static final int LINK_ORDINAL = 6;
	private static final int INFO_ORDINAL = 7;
	private static final int ALIGN_ORDINAL = 8;
	private static final int ENTRY_SIZE_ORDINAL = 9;

	public ElfSectionData(Data data) {
		super(data);
	}

	private long getNameIndex() {
		return getValue(NAME_ORDINAL).getValue();
	}

	private AddressSpace getSpace() {
		return getBlock().getStart().getAddressSpace();
	}

	public String getName() {
		ElfStringTable table = getSectionStringTable();
		return table.getValue(getNameIndex());

	}

	public MemoryBlock getBlock() {
		return getBlock(getName());
	}

	public long getType() {
		return getValue(TYPE_ORDINAL).getValue();
	}

	public long getFlags() {
		return getValue(FLAGS_ORDINAL).getValue();
	}

	public Address getAddress() {
		return getSpace().getAddress(getValue(ADDR_ORDINAL).getValue());
	}

	public long getOffset() {
		return getValue(OFFSET_ORDINAL).getValue();
	}

	public long getSize() {
		return getValue(SIZE_ORDINAL).getValue();
	}

	public long getLink() {
		return getValue(LINK_ORDINAL).getValue();
	}

	public long getInfo() {
		return getValue(INFO_ORDINAL).getValue();
	}

	public long getAlignment() {
		return getValue(ALIGN_ORDINAL).getValue();
	}

	public long getEntrySize() {
		return getValue(ENTRY_SIZE_ORDINAL).getValue();
	}

	public int getIndex() {
		return data.getComponentIndex();
	}

}
