package ghidra.emotionengine.elf;

import ghidra.program.model.listing.Data;

public final class ElfSectionTableData extends AbstractElfHeaderData {

	public ElfSectionTableData(Data data) {
		super(data);
	}

	public ElfSectionData getSection(String name) {
		for (int i = 0; i < data.getNumComponents(); i++) {
			ElfSectionData section = new ElfSectionData(data.getComponent(i));
			if (name.equals(section.getName())) {
				return section;
			}
		}
		return null;
	}

	public ElfSectionData getSection(int index) {
		return new ElfSectionData(data.getComponent(index));
	}

}
