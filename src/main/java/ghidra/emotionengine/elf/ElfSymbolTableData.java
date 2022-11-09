package ghidra.emotionengine.elf;

import java.util.stream.IntStream;
import java.util.stream.Stream;

import ghidra.program.model.listing.Data;

public final class ElfSymbolTableData extends AbstractElfHeaderData {

	public ElfSymbolTableData(Data data) {
		super(data);
	}

	public ElfSymbolData getSymbol(int index) {
		return new ElfSymbolData(data.getComponent(index));
	}

	public Stream<ElfSymbolData> getSymbolStream() {
		return IntStream.range(0, data.getNumComponents())
			.mapToObj(data::getComponent)
			.map(ElfSymbolData::new);
	}

}
