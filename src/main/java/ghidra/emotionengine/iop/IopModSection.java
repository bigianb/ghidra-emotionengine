package ghidra.emotionengine.iop;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.elf.ElfHeader;
import ghidra.app.util.bin.format.elf.ElfLoadHelper;
import ghidra.app.util.bin.format.elf.ElfSectionHeader;
import ghidra.emotionengine.EmotionEngineElfSection;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Data;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.program.model.scalar.Scalar;
import ghidra.util.task.TaskMonitor;

import static ghidra.app.util.bin.format.elf.extend.MIPS_ElfExtension.MIPS_GP_VALUE_SYMBOL;

import java.io.IOException;

public final class IopModSection implements EmotionEngineElfSection {

	private static final String IOP_MOD_STRUCTURE_NAME = "_Elf32_IopMod";
	private static final String BSS_SECTION_NAME = ".bss";

	private final Data data;
	private final ElfLoadHelper elf;

	public IopModSection(ElfSectionHeader header, ElfLoadHelper elf) {
		this.elf = elf;
		BinaryReader reader = header.getReader();
		Structure struct = getIopModHeader();
		String name;
		try {
			name = reader.readAsciiString(header.getOffset() + struct.getLength());
		} catch (IOException e) {
			elf.log(e);
			name = "";
		}
		struct.add(TerminatedStringDataType.dataType, name.length() + 1,
			"modulename", null);
		this.data = elf.createData(elf.findLoadAddress(header, 0), struct);
	}

	@Override
	public void parse(TaskMonitor monitor) throws Exception {
		Memory mem = elf.getProgram().getMemory();
		Address gpAddr = elf.getDefaultAddress(getGpValue());
		elf.createSymbol(gpAddr, MIPS_GP_VALUE_SYMBOL, false, false, null);
		elf.log(MIPS_GP_VALUE_SYMBOL + "=0x" + gpAddr.toString());
		if (mem.getBlock(BSS_SECTION_NAME) == null) {
			int bssOffset = getTextSize() + getDataSize();
			Address bssAddr = elf.getDefaultAddress(bssOffset);
			if (getBssSize() > 0) {
				try {
					mem.createUninitializedBlock(BSS_SECTION_NAME, bssAddr, getBssSize(), false);
				} catch (MemoryConflictException e) {
					e.printStackTrace();
				}
			}
		}
	}

	public int getModuleInfo() {
		return getIntValue(IopModuleComponents.MODULEINFO);
	}

	public int getEntry() {
		return getIntValue(IopModuleComponents.ENTRY);
	}

	public int getGpValue() {
		return getIntValue(IopModuleComponents.GP_VALUE);
	}

	public int getTextSize() {
		return getIntValue(IopModuleComponents.TEXT_SIZE);
	}

	public int getDataSize() {
		return getIntValue(IopModuleComponents.DATA_SIZE);
	}

	public int getBssSize() {
		return getIntValue(IopModuleComponents.BSS_SIZE);
	}

	public short getModuleVersion() {
		return (short) getIntValue(IopModuleComponents.MODULEVERSION);
	}

	private int getIntValue(IopModuleComponents comp) {
		Scalar value = (Scalar) data.getComponent(comp.ordinal()).getValue();
		return (int) value.getUnsignedValue();
	}

	private static Structure getIopModHeader() {
		Structure struct =
			new StructureDataType(ELF_PATH, IOP_MOD_STRUCTURE_NAME, 0);
		struct.add(ElfHeader.DWORD, "moduleinfo", null);
		struct.add(ElfHeader.DWORD, "entry", null);
		struct.add(ElfHeader.DWORD, "gp_value", null);
		struct.add(ElfHeader.DWORD, "text_size", null);
		struct.add(ElfHeader.DWORD, "data_size", null);
		struct.add(ElfHeader.DWORD, "bss_size", null);
		struct.add(ElfHeader.WORD, "moduleversion", null);
		return struct;
	}

	private static enum IopModuleComponents {
		MODULEINFO,
		ENTRY,
		GP_VALUE,
		TEXT_SIZE,
		DATA_SIZE,
		BSS_SIZE,
		MODULEVERSION
	};
}
