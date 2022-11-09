package ghidra.emotionengine.data;

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

import ghidra.docking.settings.Settings;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.BooleanDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DataImage;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DynamicDataType;
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.FloatDataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.data.QWordDataType;
import ghidra.program.model.data.ReadOnlyDataTypeComponent;
import ghidra.program.model.data.Resource;
import ghidra.program.model.data.SignedQWordDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.TypedefDataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBufferImpl;
import ghidra.util.Msg;
import ghidra.util.exception.AssertException;

import javax.swing.ImageIcon;
import java.awt.Point;
import java.awt.image.*;

@SuppressWarnings("unused")
public class GifPacketDataType extends DynamicDataType implements Resource {

	private static final String NAME = "gifPacket";
	private static final String DESCRIPTION =
		"Dynamic representation of the Emotino Engine gif packet";

	private enum TagType {
		PACKED,
		REGLIST,
		IMAGE,
		NONE
	};

	private enum PackedRegisterDescriptor {
		PRIM,
		RGBAQ,
		ST,
		UV,
		XYZF2,
		XYZ2,
		TEX0_1,
		TEX0_2,
		CLAMP_1,
		CLAMP_2,
		FOG,
		XYZF3,
		XYZ3,
		A_D,
		NOP
	}

	private static final PackedRegisterDescriptor[] DESCRIPTORS = new PackedRegisterDescriptor[]{
		PackedRegisterDescriptor.PRIM,
		PackedRegisterDescriptor.RGBAQ,
		PackedRegisterDescriptor.ST,
		PackedRegisterDescriptor.UV,
		PackedRegisterDescriptor.XYZF2,
		PackedRegisterDescriptor.XYZ2,
		PackedRegisterDescriptor.TEX0_1,
		PackedRegisterDescriptor.TEX0_2,
		PackedRegisterDescriptor.CLAMP_1,
		PackedRegisterDescriptor.CLAMP_2,
		PackedRegisterDescriptor.FOG,
		null,
		PackedRegisterDescriptor.XYZF3,
		PackedRegisterDescriptor.XYZ3,
		PackedRegisterDescriptor.A_D,
		PackedRegisterDescriptor.NOP
	};

	private static final int REGISTER_DESCRIPTOR_ARRAY_OFFSET = 8;
	private static final int INT_SIZE = 4;
	private static final int LONG_SIZE = 8;
	private static final int GIF_TAG_SIZE = 16;

	private static final String GIF_TAG = "gifTag";
	private static final String PACK_AD = "gsGifPackAD";

	public GifPacketDataType() {
		super(NAME);
	}

	public GifPacketDataType(DataTypeManager dtm) {
		super(NAME, dtm);
	}

	@Override
	public DataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		return new GifPacketDataType(dtm);
	}

	@Override
	public String getDescription() {
		return DESCRIPTION;
	}

	@Override
	public Object getValue(MemBuffer buf, Settings settings, int length) {
		// TODO return a DataImage if applicable
		return new GifPacketImage(this, buf);
	}

	@Override
	public String getRepresentation(MemBuffer buf, Settings settings, int length) {
		return "<GifPacket-Image>";
	}

	@Override
	public DataType getReplacementBaseType() {
		return getGifTag(getDataTypeManager());
	}

	private static DataType getU64() {
		return new TypedefDataType("u64", QWordDataType.dataType);
	}

	private static DataType getS64() {
		return new TypedefDataType("s64", SignedQWordDataType.dataType);
	}

	@Override
	protected DataTypeComponent[] getAllComponents(MemBuffer buf) {
		return new SubGifPacketImage(this, buf).getAllComponents();
	}

	private static DataTypeComponent getReglistArray(MemoryBufferImpl tmpBuf) {
		Msg.error(GifPacketDataType.class, "getReglistArray called.");
		return null;
	}

	private static int getLoopCount(MemBuffer buf) {
		try {
			return buf.getInt(0) & 0x7FFF;
		} catch (MemoryAccessException e) {
			return 0;
		}
	}

	private static boolean isEndOfPacket(MemoryBufferImpl buf,
		List<DataTypeComponent> comps, Address start) {
			try {
				boolean result = (buf.getByte(1) & 0x8000) > 0;
				buf.setPosition(start.add(getNextOffset(comps)));
				return result;
			} catch (MemoryAccessException e) {
				return true;
			}
	}

	private static int getNextOffset(List<DataTypeComponent> comps) {
		if (comps.isEmpty()) {
			return 0;
		}
		return comps.get(comps.size() -1).getEndOffset()+1;
	}

	private static int getNextOrdinal(List<DataTypeComponent> comps) {
		if (comps.isEmpty()) {
			return 0;
		}
		return comps.get(comps.size() -1).getOrdinal()+1;
	}

	private static TagType getTagType(MemBuffer buf) {
		try {
			switch ((buf.getByte(7) & 0xC) >> 2) {
				case 0:
					return TagType.PACKED;
				case 1:
					return TagType.REGLIST;
				case 2:
					return TagType.IMAGE;
				case 3:
					return TagType.NONE;
				default:
					// impossible
					throw new AssertException("Invalid tag type at "+buf.getAddress().toString());
			}
		} catch (MemoryAccessException e) {
			Msg.error(GifPacketDataType.class, e);
			return null;
		}
	}

	private static Structure getGifPackRgbaq() {
		StructureDataType struct = new StructureDataType("gsGifPackRGBAQ", 0);
		struct.add(UnsignedIntegerDataType.dataType, INT_SIZE, "R", null);
		struct.add(UnsignedIntegerDataType.dataType, INT_SIZE, "G", null);
		struct.add(UnsignedIntegerDataType.dataType, INT_SIZE, "B", null);
		struct.add(UnsignedIntegerDataType.dataType, INT_SIZE, "A", null);
		return struct;
	}

	private static Structure getGifPackAd(MemBuffer buf) {

		StructureDataType struct;
		DataType gsRegister = GsRegister.getEnumDataType();
		try {
			int type = buf.getByte(8);
			GsRegister reg = GsRegister.getGsRegister(type);
			DataType regType = reg.getDataType();
			struct = new StructureDataType(PACK_AD+"_"+regType.getName(), 0);
			struct.add(regType, "DATA", null);
		} catch (MemoryAccessException e) {
			struct = new StructureDataType(PACK_AD, 0);
			struct.add(getU64(), "DATA", null);
		}
		struct.add(gsRegister, LONG_SIZE, "ADDR", null);
		return struct;
	}

	private static Structure getGifPackSt() {
		StructureDataType struct = new StructureDataType("gsGifPackST", 0);
		struct.add(FloatDataType.dataType, INT_SIZE, "S", null);
		struct.add(FloatDataType.dataType, INT_SIZE, "T", null);
		struct.add(FloatDataType.dataType, INT_SIZE, "Q", null);
		struct.add(UnsignedIntegerDataType.dataType, INT_SIZE, "pad", null);
		return struct;
	}

	private static Structure getGifPackUv() {
		StructureDataType struct = new StructureDataType("gsGifPackUV", 0);
		struct.add(IntegerDataType.dataType, INT_SIZE, "U", null);
		struct.add(IntegerDataType.dataType, INT_SIZE, "V", null);
		struct.add(getS64(), LONG_SIZE, "pad64", null);
		return struct;
	}

	private static Structure getGifPackXyzf() {
		StructureDataType struct = new StructureDataType("gsGifPackXYZF", 0);
		try {
			struct.add(IntegerDataType.dataType, INT_SIZE, "X", null);
			struct.add(IntegerDataType.dataType, INT_SIZE, "Y", null);
			struct.add(UnsignedIntegerDataType.dataType, INT_SIZE, "Z", null);
			struct.addBitField(UnsignedIntegerDataType.dataType, 12, "F", null);
			struct.addBitField(UnsignedIntegerDataType.dataType, 3, "pad0", null);
			struct.addBitField(UnsignedIntegerDataType.dataType, 1, "ADC", null);
			struct.addBitField(UnsignedIntegerDataType.dataType, 16, "pad1", null);
			return struct;
		}
		catch (InvalidDataTypeException e) {
			Msg.error(GifPacketDataType.class, e);
			return null;
		}
	}

	private static Structure getGifPackXyz() {
		StructureDataType struct = new StructureDataType("gsGifPackXYZ", 0);
		try {
			struct.add(IntegerDataType.dataType, INT_SIZE, "X", null);
			struct.add(IntegerDataType.dataType, INT_SIZE, "Y", null);
			struct.add(UnsignedIntegerDataType.dataType, INT_SIZE, "Z", null);
			struct.addBitField(UnsignedIntegerDataType.dataType, 15, "pad0", null);
			struct.addBitField(UnsignedIntegerDataType.dataType, 1, "ADC", null);
			struct.addBitField(UnsignedIntegerDataType.dataType, 16, "pad1", null);
			return struct;
		} catch (InvalidDataTypeException e) {
			Msg.error(GifPacketDataType.class, e);
			return null;
		}
	}

	private static Structure getGifPackFog() {
		StructureDataType struct = new StructureDataType("gsGifPackFOG", 0);
		ArrayDataType array = new ArrayDataType(
			UnsignedIntegerDataType.dataType, 3, INT_SIZE);
		struct.add(array, "pad", null);
		struct.add(UnsignedIntegerDataType.dataType, INT_SIZE, "F", null);
		return struct;
	}

	private static Structure getGifPackNop() {
		StructureDataType struct = new StructureDataType("gsGifPackNOP", 0);
		ArrayDataType array = new ArrayDataType(
			getU64(), 2, LONG_SIZE);
		struct.add(array, "pad", null);
		return struct;
	}

	private static PackedRegisterDescriptor getDescriptorType(MemBuffer buf, boolean upper) {
		try {
			int value = upper ? buf.getByte(0) >> 4 : buf.getByte(0) & 0xF;
			return DESCRIPTORS[value];
		} catch (MemoryAccessException e) {
			Msg.error(GifPacketDataType.class, e);
			return null;
		}
	}

	private static int getNumDescriptors(MemBuffer buf) {
		try {
			return buf.getByte(7) >> 4;
		} catch (MemoryAccessException e) {
			return 0;
		}
	}

	private static Structure getGifTag(DataTypeManager dtm) {
		StructureDataType struct = new StructureDataType(GIF_TAG, 0, dtm);
		DataType uLong = getU64();
		DataType regDescriptor = getRegisterDescriptor();
		try {
			struct.setExplicitMinimumAlignment(LONG_SIZE);
			struct.addBitField(uLong, 15, "NLOOP", null);
			struct.addBitField(BooleanDataType.dataType, 1, "EOP", null);
			struct.addBitField(uLong, 16, "pad16", null);
			struct.addBitField(uLong, 14, "id", null);
			struct.addBitField(BooleanDataType.dataType, 1, "PRE", null);
			struct.addBitField(uLong, 11, "PRIM", null);
			struct.addBitField(getFlag(), 2, "FLG", null);
			struct.addBitField(uLong, 4, "NREG", null);
			for (int i = 0; i < 16; i++) {
				struct.addBitField(regDescriptor, 4, "REGS"+Integer.toString(i), null);
			}
			return (Structure) dtm.resolve(struct, DataTypeConflictHandler.REPLACE_HANDLER);
		} catch (InvalidDataTypeException e) {
			Msg.error(GifPacketDataType.class, e);
			return null;
		}
	}

	private static Enum getFlag() {
		EnumDataType dt = new EnumDataType("gifTagFlag", 1);
		dt.add("PACKED", 0);
		dt.add("REGLIST", 1);
		dt.add("IMAGE", 2);
		dt.add("NONE", 3);
		return dt;
	}

	private static Enum getRegisterDescriptor() {
		EnumDataType dt = new EnumDataType("GIFtag_RegisterDescriptor", 1);
		dt.add("PRIM", 0x0);
		dt.add("RGBAQ", 0x1);
		dt.add("ST", 0x2);
		dt.add("UV", 0x3);
		dt.add("XYZF2", 0x4);
		dt.add("XYZ2", 0x5);
		dt.add("TEX0_1", 0x6);
		dt.add("TEX0_2", 0x7);
		dt.add("CLAMP_1", 0x8);
		dt.add("CLAMP_2", 0x9);
		dt.add("FOG", 0xa);
		dt.add("XYZF3", 0xc);
		dt.add("XYZ3", 0xd);
		dt.add("A+D", 0xe);
		dt.add("NOP", 0xf);
		return dt;
	}



	public class GsGifPackAD extends DynamicDataType {

		private static final String AD_NAME = "gsGifPackAD";
		private static final String AD_DESCRIPTION =
			"Dynamic representation of the packed GS AD register";

		public GsGifPackAD() {
			super(AD_NAME);
		}

		public GsGifPackAD(DataTypeManager dtm) {
			super(AD_NAME, dtm);
		}

		@Override
		public DataType clone(DataTypeManager dtm) {
			if (dtm == getDataTypeManager()) {
				return this;
			}
			return new GsGifPackAD(dtm);
		}

		@Override
		public String getDescription() {
			return AD_DESCRIPTION;
		}

		@Override
		public Object getValue(MemBuffer buf, Settings settings, int length) {
			Msg.error(this, "getValue called.");
			return null;
		}

		@Override
		public String getRepresentation(MemBuffer buf, Settings settings, int length) {
			Msg.error(this, "getRepresentation called.");
			return null;
		}

		@Override
		protected DataTypeComponent[] getAllComponents(MemBuffer buf) {
			DataTypeComponent[] comps = new DataTypeComponent[2];
			try {
				GsRegister gsReg = GsRegister.getGsRegister(buf.getInt(INT_SIZE));
				DataType reg = GsRegister.getEnumDataType();
				DataType regStruct = gsReg.getDataType();
				comps[0] = new ReadOnlyDataTypeComponent(
					regStruct, this, regStruct.getLength(), 0, 0);
				comps[1] = new ReadOnlyDataTypeComponent(
					reg, this, reg.getLength(), 1, regStruct.getLength());
			} catch (MemoryAccessException e) {
				Msg.error(this, e);
			}
			return comps;
		}

	}

	private static class GifPacketImage extends DataImage {

		private final byte[] data;
		private SubGifPacketImage packet;

		GifPacketImage() {
			this.data = new byte[0];
		}

		GifPacketImage(DynamicDataType parent, MemBuffer buf) {
			this();
			this.packet = new SubGifPacketImage(parent, buf);
		}

		@Override
		public ImageIcon getImageIcon() {
			if (packet != null && packet.dataPsm != null) {
				int bitDepth;
				GsClut clut = new GsClut(packet.clut, packet.clutPsm);
				switch (packet.dataPsm) {
					case PSMT4:
						bitDepth = 4;
						break;
					case PSMT8:
						bitDepth = 8;
						break;
					default:
						bitDepth = 8;
						break;
				}
				BufferedImage image;
				if (bitDepth == 4) {
					image = new BufferedImage(
					packet.getWidth(), packet.getHeight(), BufferedImage.TYPE_BYTE_BINARY,
					clut.getClutModel());
				} else {
					image = new BufferedImage(
					packet.getWidth(), packet.getHeight(), BufferedImage.TYPE_BYTE_INDEXED,
					clut.getClutModel());
				}
				DataBufferByte dBuf = new DataBufferByte(packet.table, packet.table.length);
				WritableRaster raster = Raster.createWritableRaster(
					image.getSampleModel(), dBuf, new Point());
				image.setData(raster);
				return new ImageIcon(image, "<GifPacket-Image>");
			}
			return new ImageIcon(data, "<GifPacket-Image>");
		}

		@Override
		public String getImageFileType() {
			return "";
		}

	}

	private static class SubGifPacketImage {

		private List<Address> bitBlitAddresses = new ArrayList<>(2);
		private List<Address> trxRegAddresses = new ArrayList<>(2);
		private List<Address> imageAddresses = new ArrayList<>(2);

		byte[] clut = null;
		byte[] table = null;
		GsPSM clutPsm;
		GsPSM dataPsm;
		private DynamicDataType parent;
		private MemBuffer buf;
		private DataTypeComponent[] components = null;

		private GsPSM getPsm(byte b) {
			switch (b & 0x3f) {
				case 0x0:
					return GsPSM.PSMCT32;
				case 0x1:
					return GsPSM.PSMCT24;
				case 0x2:
					return GsPSM.PSMCT16;
				case 0xa:
					return GsPSM.PSMCT16S;
				case 0x13:
					return GsPSM.PSMT8;
				case 0x14:
					return GsPSM.PSMT4;
				case 0x1b:
					return GsPSM.PSMT8H;
				case 0x24:
					return GsPSM.PSMT4HL;
				case 0x2c:
					return GsPSM.PSMT4HH;
				case 0x30:
					return GsPSM.PSMZ32;
				case 0x31:
					return GsPSM.PSMZ24;
				case 0x32:
					return GsPSM.PSMZ16;
				case 0x3a:
					return GsPSM.PSMZ16S;
				default:
					Msg.error(this, "Failed to determine psm type");
					return null;
			}
		}

		SubGifPacketImage(DynamicDataType parent, MemBuffer buf) {
			this.parent = parent;
			this.buf = buf;
			this.components = getAllComponents();
			if (!imageAddresses.isEmpty()) {
				fillImageData();
			}
		}

		private MemoryBufferImpl getBufferAt(Address address) {
			return new MemoryBufferImpl(buf.getMemory(), address);
		}

		private void fillImageData() {
			try {
				MemoryBufferImpl tmpBuf = getBufferAt(bitBlitAddresses.get(0));
				clutPsm = getPsm(tmpBuf.getByte(7));
				tmpBuf.setPosition(imageAddresses.get(0));
				int size = getLoopCount(tmpBuf) * GIF_TAG_SIZE;
				clut = new byte[size];
				tmpBuf.getBytes(clut, GIF_TAG_SIZE);
				tmpBuf.setPosition(bitBlitAddresses.get(1));
				dataPsm = getPsm(tmpBuf.getByte(7));
				tmpBuf.setPosition(imageAddresses.get(1));
				size = getLoopCount(tmpBuf) * GIF_TAG_SIZE;
				table = new byte[size];
				tmpBuf.getBytes(table, GIF_TAG_SIZE);
			} catch (MemoryAccessException | IndexOutOfBoundsException e) {
				Msg.debug(this, e);
			}
		}

		private int getWidth() {
			MemoryBufferImpl tmpBuf;
			if (trxRegAddresses.size() > 1) {
				tmpBuf = getBufferAt(trxRegAddresses.get(1));
			} else {
				tmpBuf = getBufferAt(trxRegAddresses.get(0));
			}
			try {
				return tmpBuf.getInt(0) & 0xfff;
			} catch (MemoryAccessException e) {
				return 0;
			}
		}

		private int getHeight() {
			MemoryBufferImpl tmpBuf;
			if (trxRegAddresses.size() > 1) {
				tmpBuf = getBufferAt(trxRegAddresses.get(1));
			} else {
				tmpBuf = getBufferAt(trxRegAddresses.get(0));
			}
			try {
				return tmpBuf.getInt(4) & 0xfff;
			} catch (MemoryAccessException e) {
				return 0;
			}
		}

		private int getClutWidth() {
			MemoryBufferImpl tmpBuf;
			tmpBuf = getBufferAt(trxRegAddresses.get(0));
			try {
				return tmpBuf.getInt(0) & 0xfff;
			} catch (MemoryAccessException e) {
				return 0;
			}
		}

		private int getClutHeight() {
			MemoryBufferImpl tmpBuf;
			tmpBuf = getBufferAt(trxRegAddresses.get(0));
			try {
				return tmpBuf.getInt(4) & 0xfff;
			} catch (MemoryAccessException e) {
				return 0;
			}
		}

		private DataTypeComponent[] getAllComponents() {
			if (components != null) {
				return components;
			}
			MemoryBufferImpl tmpBuf = new MemoryBufferImpl(buf.getMemory(), buf.getAddress());
			int count = getLoopCount(buf);
			if (count <= 0) {
				Msg.error(this, "count <= 0");
				return null;
			}
			List<DataTypeComponent> comps = new LinkedList<>();
			DataTypeManager dtm = buf.getMemory().getProgram().getDataTypeManager();
			int id = dtm.startTransaction("stupid");
			Structure gifTag = getGifTag(dtm);
			try {
				do {
					comps.add(new ReadOnlyDataTypeComponent(
						gifTag, parent, gifTag.getLength(), getNextOrdinal(comps), getNextOffset(comps)));
					switch (getTagType(tmpBuf)) {
						case PACKED:
							addPackedArray(tmpBuf, comps);
							break;
						case REGLIST:
							comps.add(getReglistArray(tmpBuf));
							break;
						case IMAGE:
						case NONE:
							addImageArray(tmpBuf, comps);
							imageAddresses.add(tmpBuf.getAddress());
							break;
						default:
							break;
					}
				} while (!isEndOfPacket(tmpBuf, comps, buf.getAddress()));
				dtm.endTransaction(id, true);
			} catch (Exception e) {
				e.printStackTrace();
				dtm.endTransaction(id, false);
			}
			components = comps.toArray(new DataTypeComponent[comps.size()]);
			return components;
		}

		private void addImageArray(MemBuffer buf, List<DataTypeComponent> comps) {
			int loopCount = getLoopCount(buf);
			ArrayDataType array = new ArrayDataType(ByteDataType.dataType, 0x10, 1);
			for (int i = 0; i < loopCount; i++) {
				comps.add(new ReadOnlyDataTypeComponent(
					array, parent, array.getLength(), getNextOrdinal(comps), getNextOffset(comps)));
			}
		}

		private void addPackedArray(MemBuffer buf, List<DataTypeComponent> comps) throws Exception {
			int loopCount = getLoopCount(buf);
			int numDescriptors = getNumDescriptors(buf);
			if (numDescriptors == 0) {
				throw new Exception("Invalid GifPacket");
			}
			List<PackedRegisterDescriptor> descriptors = new ArrayList<>(numDescriptors);
			MemoryBufferImpl tmpBuf = new MemoryBufferImpl(
				buf.getMemory(), buf.getAddress().add(REGISTER_DESCRIPTOR_ARRAY_OFFSET));
			for (int i = 0; i < numDescriptors; i++) {
				boolean upper = (i & 1) == 1;
				descriptors.add(getDescriptorType(tmpBuf, upper));
				if (upper) {
					try {
						tmpBuf.advance(1);
					} catch (AddressOverflowException e) {
						return;
					}
				}
			}
			tmpBuf.setPosition(buf.getAddress().add(REGISTER_DESCRIPTOR_ARRAY_OFFSET << 1));
			for (int i = 0; i < loopCount; i++) {
				for (PackedRegisterDescriptor descriptor : descriptors) {
					DataType dt = getDescriptorDataType(descriptor, tmpBuf);
					if (dt.getName().startsWith(PACK_AD)) {
						DataType subType = ((Structure) dt).getComponent(0).getDataType();
						if (subType.getName().contains(GsRegister.GS_BIT_BLT)) {
							bitBlitAddresses.add(tmpBuf.getAddress());
						} else if (subType.getName().contains(GsRegister.GS_TRX_REG)) {
							trxRegAddresses.add(tmpBuf.getAddress());
						}
					}
					comps.add(new ReadOnlyDataTypeComponent(
						dt, parent, dt.getLength(), getNextOrdinal(comps), getNextOffset(comps)));
					try {
						tmpBuf.advance(dt.getLength());
					} catch (AddressOverflowException e) {
						return;
					}
				}
			}
		}

		private DataType getDescriptorDataType(PackedRegisterDescriptor descriptor, MemBuffer buf) {
			switch (descriptor) {
				case A_D:
					return getGifPackAd(buf);
				case FOG:
					return getGifPackFog();
				case NOP:
					return getGifPackNop();
				case RGBAQ:
					return getGifPackRgbaq();
				case ST:
					return getGifPackSt();
				case UV:
					return getGifPackUv();
				case XYZ2:
				case XYZ3:
					return getGifPackXyz();
				case XYZF2:
				case XYZF3:
					return getGifPackXyzf();
				default:
					Msg.error(this, "getDescriptorDataType default case");
					return null;
			}
		}

	}

}
