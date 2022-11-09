package ghidra.emotionengine.importer;

import java.io.IOException;
import java.io.InputStream;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.data.*;
import ghidra.util.Msg;
import ghidra.util.NumericUtilities;

import static ghidra.emotionengine.EmotionEngineUtil.MW_PATH;

final class MwOverlay {
	
	public static final DataType dataType = getDataType();

	private final byte version;
	private final int id;
	private final int address;
	private final int textSize;
	private final int dataSize;
	private final int bssSize;
	private final int staticInitStart;
	private final int staticInitEnd;
	private final String name;
	private final ByteProvider provider;

	private MwOverlay(ByteProvider provider) throws IOException {
		BinaryReader reader = new BinaryReader(provider, true);
		if (!reader.readNextAsciiString(3).equals("MWo")) {
			throw new IllegalArgumentException("Invalid Overlay");
		}
		this.provider = provider;
		this.version = reader.readNextByte();
		this.id = reader.readNextInt();
		this.address = reader.readNextInt();
		this.textSize = reader.readNextInt();
		this.dataSize = reader.readNextInt();
		this.bssSize = reader.readNextInt();
		this.staticInitStart = reader.readNextInt();
		this.staticInitEnd = reader.readNextInt();
		this.name = reader.readNextAsciiString();
	}

	static MwOverlay get(ByteProvider provider) {
		try {
			return new MwOverlay(provider);
		} catch (Exception e) {
			Msg.error(MwOverlay.class, e);
			return null;
		}
	}

	/**
	 * @return the version
	 */
	byte getVersion() {
		return version;
	}

	/**
	 * @return the id
	 */
	int getId() {
		return id;
	}

	/**
	 * @return the address
	 */
	int getAddress() {
		return address;
	}

	/**
	 * @param AddressFactory the address factory
	 * @return the address
	 */
	Address getAddress(AddressFactory factory) {
		String addr = NumericUtilities.toHexString(Integer.toUnsignedLong(address));
		return factory.getAddress(addr);
	}

	/**
	 * @return the textSize
	 */
	int getTextSize() {
		return textSize;
	}

	/**
	 * @return the dataSize
	 */
	int getDataSize() {
		return dataSize;
	}

	/**
	 * @return the bssSize
	 */
	int getBssSize() {
		return bssSize;
	}

	/**
	 * @return the staticInitStart
	 */
	int getStaticInitStart() {
		return staticInitStart;
	}

	/**
	 * @return the staticInitEnd
	 */
	int getStaticInitEnd() {
		return staticInitEnd;
	}

	/**
	 * @return the name
	 */
	String getName() {
		return name;
	}

	/**
	 * @return the data as an input stream
	 * @throws IOException
	 */
	InputStream getDataStream() throws IOException {
		return provider.getInputStream(0);
	}

	long getSize() throws IOException {
		return provider.length();
	}

	private static DataType getDataType() {
		Structure struct = new StructureDataType(MW_PATH, "mwOverlayHeader", 0);
		Array array = new ArrayDataType(CharDataType.dataType, 3, 1);
		struct.add(array, "identifier", "MWo");
		struct.add(ByteDataType.dataType, "version", null);
		struct.add(DWordDataType.dataType, "id", null);
		struct.add(DWordDataType.dataType, "address", null);
		struct.add(DWordDataType.dataType, "sz_text", null);
		struct.add(DWordDataType.dataType, "sz_data", null);
		struct.add(DWordDataType.dataType, "sz_bss", null);
		struct.add(DWordDataType.dataType, "_static_init", null);
		struct.add(DWordDataType.dataType, "_static_init_end", null);
		array = new ArrayDataType(CharDataType.dataType, 32, 1);
		struct.add(array, "name", null);
		return struct;
	}

	/**
	 * @return the mwPath
	 */
	static CategoryPath getMwPath() {
		return MW_PATH;
	}
}
