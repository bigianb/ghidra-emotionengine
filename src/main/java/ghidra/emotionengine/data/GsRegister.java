package ghidra.emotionengine.data;

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.FloatDataType;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.data.QWordDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.TypedefDataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.util.Msg;

enum GsRegister {
	PRIM(0),
	RGBAQ(1),
	ST(2),
	UV(3),
	XYZF2(4),
	XYZ2(5),
	TEX0_1(6),
	TEX0_2(7),
	CLAMP_1(8),
	CLAMP_2(9),
	FOG(0xa),
	XYZF3(0xc),
	XYZ3(0xd),
	TEX1_1(0x14),
	TEX1_2(0x15),
	TEX2_1(0x16),
	TEX2_2(0x17),
	XYOFFSET_1(0x18),
	XYOFFSET_2(0x19),
	PRMODECONT(0x1a),
	PRMODE(0x1b),
	TEXCLUT(0x1c),
	SCANMSK(0x22),
	MIPTBP1_1(0x34),
	MIPTBP1_2(0x35),
	MIPTBP2_1(0x36),
	MIPTBP2_2(0x37),
	TEXA(0x3b),
	FOGCOL(0x3d),
	TEXFLUSH(0x3f),
	SCISSOR_1(0x40),
	SCISSOR_2(0x41),
	ALPHA_1(0x42),
	ALPHA_2(0x43),
	DIMX(0x44),
	DTHE(0x45),
	COLCLAMP(0x46),
	TEST_1(0x47),
	TEST_2(0x48),
	PABE(0x49),
	FBA_1(0x4a),
	FBA_2(0x4b),
	FRAME_1(0x4c),
	FRAME_2(0x4d),
	ZBUF_1(0x4e),
	ZBUF_2(0x4f),
	BITBLTBUF(0x50),
	TRXPOS(0x51),
	TRXREG(0x52),
	TRXDIR(0x53),
	HWREG(0x54),
	SIGNAL(0x60),
	FINISH(0x61),
	LABEL(0x62);

	private static final int INT_SIZE = 4;
	private static final int LONG_SIZE = 8;
	protected static final String GS_BIT_BLT = "GsBitBlt";
	protected static final String GS_TRX_REG = "GsTrxReg";
	private int value;
	private DataType dataType;

	GsRegister(int value) {
		this.value = value;
		this.dataType = doGetDataType();
	}

	static GsRegister getGsRegister(int value) {
		for (GsRegister psm : GsRegister.values()) {
			if (psm.value == value) {
				return psm;
			}
		}
		return null;
	}

	DataType getDataType() {
		return dataType;
	}

	private DataType doGetDataType() {
		switch (value) {
			case 0x0:
				return getGsPrim();
			case 0x1:
				return getGsRgbaq();
			case 0x2:
				return getGsSt();
			case 0x3:
				return getGsUv();
			case 0x4:
				return getGsXYZF();
			case 0x5:
				return getGsXYZ();
			case 0x6:
			case 0x7:
				return getGsTex0();
			case 0x8:
			case 0x9:
				return getGsClamp();
			case 0xa:
				return getGsFog();
			case 0xc:
				return getGsXYZF();
			case 0xd:
				return getGsXYZ();
			case 0x14:
			case 0x15:
				return getGsTex1();
			case 0x16:
			case 0x17:
				return getGsTex2();
			case 0x18:
			case 0x19:
				return getGsXyoffset();
			case 0x1a:
				return getGsPrModeCont();
			case 0x1b:
				return getGsPrMode();
			case 0x1c:
				return getGsTexClut();
			case 0x22:
				return getGsScanMsk();
			case 0x34:
			case 0x35:
				return getGsMiptbp1();
			case 0x36:
			case 0x37:
				return getGsMiptbp2();
			case 0x3b:
				return getGsTexA();
			case 0x3d:
				return getGsFogCol();
			case 0x3f:
				return getGsTexFlush();
			case 0x40:
			case 0x41:
				return getGsScissor();
			case 0x42:
			case 0x43:
				return getGsAlpha();
			case 0x44:
				return getGsDimx();
			case 0x45:
				return getGsDthe();
			case 0x46:
				return getGsColClamp();
			case 0x47:
			case 0x48:
				return getGsTest();
			case 0x49:
				return getGsPabe();
			case 0x4a:
			case 0x4b:
				return getGsFba();
			case 0x4c:
			case 0x4d:
				return getGsFrame();
			case 0x4e:
			case 0x4f:
				return getGsZbuf();
			case 0x50:
				return getGsBitBltBuf();
			case 0x51:
				return getGsTrxPos();
			case 0x52:
				return getGsTrxReg();
			case 0x53:
				return getGsTrxDir();
			case 0x54:
				return getGsHwReg();
			case 0x60:
				return getGsSignal();
			case 0x61:
				return getGsFinish();
			case 0x62:
				return getGsLabel();
			default:
				Msg.error(GsRegister.class, "getDataType returning null");
				return null;
		}
	}

	static Enum getEnumDataType() {
		EnumDataType dt = new EnumDataType("GS_REGISTERS", 8);
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
		dt.add("TEX1_1", 0x14);
		dt.add("TEX1_2", 0x15);
		dt.add("TEX2_1", 0x16);
		dt.add("TEX2_2", 0x17);
		dt.add("XYOFFSET_1", 0x18);
		dt.add("XYOFFSET_2", 0x19);
		dt.add("PRMODECONT", 0x1a);
		dt.add("PRMODE", 0x1b);
		dt.add("TEXCLUT", 0x1c);
		dt.add("SCANMSK", 0x22);
		dt.add("MIPTBP1_1", 0x34);
		dt.add("MIPTBP1_2", 0x35);
		dt.add("MIPTBP2_1", 0x36);
		dt.add("MIPTBP2_2", 0x37);
		dt.add("TEXA", 0x3b);
		dt.add("FOGCOL", 0x3d);
		dt.add("TEXFLUSH", 0x3f);
		dt.add("SCISSOR_1", 0x40);
		dt.add("SCISSOR_2", 0x41);
		dt.add("ALPHA_1", 0x42);
		dt.add("ALPHA_2", 0x43);
		dt.add("DIMX", 0x44);
		dt.add("DTHE", 0x45);
		dt.add("COLCLAMP", 0x46);
		dt.add("TEST_1", 0x47);
		dt.add("TEST_2", 0x48);
		dt.add("PABE", 0x49);
		dt.add("FBA_1", 0x4a);
		dt.add("FBA_2", 0x4b);
		dt.add("FRAME_1", 0x4c);
		dt.add("FRAME_2", 0x4d);
		dt.add("ZBUF_1", 0x4e);
		dt.add("ZBUF_2", 0x4f);
		dt.add("BITBLTBUF", 0x50);
		dt.add("TRXPOS", 0x51);
		dt.add("TRXREG", 0x52);
		dt.add("TRXDIR", 0x53);
		dt.add("HWREG", 0x54);
		dt.add("SIGNAL", 0x60);
		dt.add("FINISH", 0x61);
		dt.add("LABEL", 0x62);
		return dt;
	}
	
	private static DataType getGsAlpha() {
		StructureDataType struct = new StructureDataType("GsAlpha", 0);
		DataType uLong = getU64();
		try {
			struct.addBitField(uLong, 2, "A", null);
			struct.addBitField(uLong, 2, "B", null);
			struct.addBitField(uLong, 2, "C", null);
			struct.addBitField(uLong, 2, "D", null);
			struct.addBitField(uLong, 24, "pad8", null);
			struct.addBitField(uLong, 8, "FIX", null);
			struct.addBitField(uLong, 24, "pad40", null);
			struct.setExplicitMinimumAlignment(LONG_SIZE);
			return struct;
		} catch (InvalidDataTypeException e) {
			Msg.error(GsRegister.class, e);
			return null;
		}
	}
	
	private static DataType getGsBitBltBuf() {
		StructureDataType struct = new StructureDataType(GS_BIT_BLT, 0);
		DataType uLong = getU64();
		DataType bitblt = getBitBltTypeDataType();
		try {
			struct.addBitField(uLong, 14, "SBP", null);
			struct.addBitField(uLong, 2, "pad14", null);
			struct.addBitField(uLong, 6, "SBW", null);
			struct.addBitField(uLong, 2, "pad22", null);
			struct.addBitField(bitblt, 6, "SPSM", null);
			struct.addBitField(uLong, 2, "pad30", null);
			struct.addBitField(uLong, 14, "DBP", null);
			struct.addBitField(uLong, 2, "pad46", null);
			struct.addBitField(uLong, 6, "DBW", null);
			struct.addBitField(uLong, 2, "pad54", null);
			struct.addBitField(bitblt, 6, "DPSM", null);
			struct.addBitField(uLong, 2, "pad62", null);
			struct.setExplicitMinimumAlignment(LONG_SIZE);
			return struct;
		} catch (InvalidDataTypeException e) {
			Msg.error(GsRegister.class, e);
			return null;
		}
	}

	private static Enum getBitBltTypeDataType() {
		EnumDataType dt = new EnumDataType("BITBLT_PSM", 1);
		dt.add("PSMCT32", 0x0);
		dt.add("PSMCT24", 0x1);
		dt.add("PSMCT16", 0x2);
		dt.add("PSMCT16S", 0xa);
		dt.add("PSMT8", 0x13);
		dt.add("PSMT4", 0x14);
		dt.add("PSMT8H", 0x1b);
		dt.add("PSMT4HL", 0x24);
		dt.add("PSMT4HH", 0x2c);
		dt.add("PSMZ32", 0x30);
		dt.add("PSMZ24", 0x31);
		dt.add("PSMZ16", 0x32);
		dt.add("PSMZ16S", 0x3a);
		return dt;
	}
	
	private static DataType getGsClamp() {
		StructureDataType struct = new StructureDataType("GsClamp", 0);
		DataType uLong = getU64();
		try {
			struct.addBitField(uLong, 2, "WMS", null);
			struct.addBitField(uLong, 2, "WMT", null);
			struct.addBitField(uLong, 10, "MINU", null);
			struct.addBitField(uLong, 10, "MAXU", null);
			struct.addBitField(uLong, 10, "MINV", null);
			struct.addBitField(uLong, 10, "MAXV", null);
			struct.addBitField(uLong, 20, "pad44", null);
			struct.setExplicitMinimumAlignment(LONG_SIZE);
			return struct;
		} catch (InvalidDataTypeException e) {
			Msg.error(GsRegister.class, e);
			return null;
		}
	}
	
	private static DataType getGsColClamp() {
		StructureDataType struct = new StructureDataType("GsColClamp", 0);
		DataType uLong = getU64();
		try {
			struct.addBitField(uLong, 1, "CLAMP", null);
			struct.addBitField(uLong, 63, "pad01", null);
			struct.setExplicitMinimumAlignment(LONG_SIZE);
			return struct;
		} catch (InvalidDataTypeException e) {
			Msg.error(GsRegister.class, e);
			return null;
		}
	}
	
	private static DataType getGsDimx() {
		StructureDataType struct = new StructureDataType("GsDimx", 0);
		DataType uLong = getU64();
		try {
			struct.addBitField(uLong, 3, "DIMX00", null);
			struct.addBitField(uLong, 1, "pad00", null);
			struct.addBitField(uLong, 3, "DIMX01", null);
			struct.addBitField(uLong, 1, "pad01", null);
			struct.addBitField(uLong, 3, "DIMX02", null);
			struct.addBitField(uLong, 1, "pad02", null);
			struct.addBitField(uLong, 3, "DIMX03", null);
			struct.addBitField(uLong, 1, "pad03", null);
		
			struct.addBitField(uLong, 3, "DIMX10", null);
			struct.addBitField(uLong, 1, "pad10", null);
			struct.addBitField(uLong, 3, "DIMX11", null);
			struct.addBitField(uLong, 1, "pad11", null);
			struct.addBitField(uLong, 3, "DIMX12", null);
			struct.addBitField(uLong, 1, "pad12", null);
			struct.addBitField(uLong, 3, "DIMX13", null);
			struct.addBitField(uLong, 1, "pad13", null);
		
			struct.addBitField(uLong, 3, "DIMX20", null);
			struct.addBitField(uLong, 1, "pad20", null);
			struct.addBitField(uLong, 3, "DIMX21", null);
			struct.addBitField(uLong, 1, "pad21", null);
			struct.addBitField(uLong, 3, "DIMX22", null);
			struct.addBitField(uLong, 1, "pad22", null);
			struct.addBitField(uLong, 3, "DIMX23", null);
			struct.addBitField(uLong, 1, "pad23", null);
		
			struct.addBitField(uLong, 3, "DIMX30", null);
			struct.addBitField(uLong, 1, "pad30", null);
			struct.addBitField(uLong, 3, "DIMX31", null);
			struct.addBitField(uLong, 1, "pad31", null);
			struct.addBitField(uLong, 3, "DIMX32", null);
			struct.addBitField(uLong, 1, "pad32", null);
			struct.addBitField(uLong, 3, "DIMX33", null);
			struct.addBitField(uLong, 1, "pad33", null);
			struct.setExplicitMinimumAlignment(LONG_SIZE);
			return struct;
		} catch (InvalidDataTypeException e) {
			Msg.error(GsRegister.class, e);
			return null;
		}
	}
	
	private static DataType getGsDthe() {
		StructureDataType struct = new StructureDataType("GsDthe", 0);
		DataType uLong = getU64();
		try {
			struct.addBitField(uLong, 1, "DTHE", null);
			struct.addBitField(uLong, 63, "pad01", null);
			struct.setExplicitMinimumAlignment(LONG_SIZE);
			return struct;
		} catch (InvalidDataTypeException e) {
			Msg.error(GsRegister.class, e);
			return null;
		}
	}
	
	private static DataType getGsFba() {
		StructureDataType struct = new StructureDataType("GsFba", 0);
		DataType uLong = getU64();
		try {
			struct.addBitField(uLong, 1, "FBA", null);
			struct.addBitField(uLong, 63, "pad01", null);
			struct.setExplicitMinimumAlignment(LONG_SIZE);
			return struct;
		} catch (InvalidDataTypeException e) {
			Msg.error(GsRegister.class, e);
			return null;
		}
	}
	
	private static DataType getGsFinish() {
		DataType uLong = getU64();
		return new TypedefDataType("GsFinish", uLong);
	}
	
	private static DataType getGsFog() {
		StructureDataType struct = new StructureDataType("GsFog", 0);
		DataType uLong = getU64();
		try {
			struct.addBitField(uLong, 56, "pad00", null);
			struct.addBitField(uLong, 8, "F", null);
			struct.setExplicitMinimumAlignment(LONG_SIZE);
			return struct;
		} catch (InvalidDataTypeException e) {
			Msg.error(GsRegister.class, e);
			return null;
		}
	}
	  
	private static DataType getGsFogCol() {
		StructureDataType struct = new StructureDataType("GsFogCol", 0);
		DataType uLong = getU64();
		try {
			struct.addBitField(uLong, 8, "FCR", null);
			struct.addBitField(uLong, 8, "FCG", null);
			struct.addBitField(uLong, 8, "FCB", null);
			struct.addBitField(uLong, 40, "pad24", null);
			struct.setExplicitMinimumAlignment(LONG_SIZE);
			return struct;
		} catch (InvalidDataTypeException e) {
			Msg.error(GsRegister.class, e);
			return null;
		}
	}
	
	private static DataType getGsFrame() {
		StructureDataType struct = new StructureDataType("GsFrame", 0);
		DataType uLong = getU64();
		try {
			struct.addBitField(uLong, 9, "FBP", null);
			struct.addBitField(uLong, 7, "pad09", null);
			struct.addBitField(uLong, 6, "FBW", null);
			struct.addBitField(uLong, 2, "pad22", null);
			struct.addBitField(uLong, 6, "PSM", null);
			struct.addBitField(uLong, 2, "pad30", null);
			struct.addBitField(uLong, 32, "FBMSK", null);
			struct.setExplicitMinimumAlignment(LONG_SIZE);
			return struct;
		} catch (InvalidDataTypeException e) {
			Msg.error(GsRegister.class, e);
			return null;
		}
	}
	
	private static DataType getGsHwReg() {
		DataType uLong = getU64();
		return new TypedefDataType("GsHwReg", uLong);
	}
	
	private static DataType getGsLabel() {
		StructureDataType struct = new StructureDataType("GsLabel", 0);
		struct.add(UnsignedIntegerDataType.dataType, INT_SIZE, "ID", null);
		struct.add(UnsignedIntegerDataType.dataType, INT_SIZE, "IDMSK", null);
		struct.setExplicitMinimumAlignment(LONG_SIZE);
			return struct;
	}
	
	private static DataType getGsMiptbp1() {
		StructureDataType struct = new StructureDataType("GsMipTbp1", 0);
		DataType uLong = getU64();
		try {
			struct.addBitField(uLong, 14, "TBP1", null);
			struct.addBitField(uLong, 6, "TBW1", null);
			struct.addBitField(uLong, 14, "TBP2", null);
			struct.addBitField(uLong, 6, "TBW2", null);
			struct.addBitField(uLong, 14, "TBP3", null);
			struct.addBitField(uLong, 6, "TBW3", null);
			struct.addBitField(uLong, 4, "pad60", null);
			struct.setExplicitMinimumAlignment(LONG_SIZE);
			return struct;
		} catch (InvalidDataTypeException e) {
			Msg.error(GsRegister.class, e);
			return null;
		}
	}
	
	private static DataType getGsMiptbp2() {
		StructureDataType struct = new StructureDataType("GsMipTbp2", 0);
		DataType uLong = getU64();
		try {
			struct.addBitField(uLong, 14, "TBP4", null);
			struct.addBitField(uLong, 6, "TBW4", null);
			struct.addBitField(uLong, 14, "TBP5", null);
			struct.addBitField(uLong, 6, "TBW5", null);
			struct.addBitField(uLong, 14, "TBP6", null);
			struct.addBitField(uLong, 6, "TBW6", null);
			struct.addBitField(uLong, 4, "pad60", null);
			struct.setExplicitMinimumAlignment(LONG_SIZE);
			return struct;
		} catch (InvalidDataTypeException e) {
			Msg.error(GsRegister.class, e);
			return null;
		}
	}
	
	private static DataType getGsPabe() {
		StructureDataType struct = new StructureDataType("GsPabe", 0);
		DataType uLong = getU64();
		try {
			struct.addBitField(uLong, 1, "PABE", null);
			struct.addBitField(uLong, 63, "pad01", null);
			struct.setExplicitMinimumAlignment(LONG_SIZE);
			return struct;
		} catch (InvalidDataTypeException e) {
			Msg.error(GsRegister.class, e);
			return null;
		}
	}
	
	private static DataType getGsPrim() {
		StructureDataType struct = new StructureDataType("GsPrim", 0);
		DataType uLong = getU64();
		try {
			struct.addBitField(uLong, 3, "PRIM", null);
			struct.addBitField(uLong, 1, "IIP", null);
			struct.addBitField(uLong, 1, "TME", null);
			struct.addBitField(uLong, 1, "FGE", null);
			struct.addBitField(uLong, 1, "ABE", null);
			struct.addBitField(uLong, 1, "AA1", null);
			struct.addBitField(uLong, 1, "FST", null);
			struct.addBitField(uLong, 1, "CTXT", null);
			struct.addBitField(uLong, 1, "FIX", null);
			struct.addBitField(uLong, 53, "pad11", null);
			struct.setExplicitMinimumAlignment(LONG_SIZE);
			return struct;
		} catch (InvalidDataTypeException e) {
			Msg.error(GsRegister.class, e);
			return null;
		}
	}
	
	private static DataType getGsPrMode() {
		StructureDataType struct = new StructureDataType("GsPrMode", 0);
		DataType uLong = getU64();
		try {
			struct.addBitField(uLong, 3, "pad00", null);
			struct.addBitField(uLong, 1, "IIP", null);
			struct.addBitField(uLong, 1, "TME", null);
			struct.addBitField(uLong, 1, "FGE", null);
			struct.addBitField(uLong, 1, "ABE", null);
			struct.addBitField(uLong, 1, "AA1", null);
			struct.addBitField(uLong, 1, "FST", null);
			struct.addBitField(uLong, 1, "CTXT", null);
			struct.addBitField(uLong, 1, "FIX", null);
			struct.addBitField(uLong, 53, "pad11", null);
			struct.setExplicitMinimumAlignment(LONG_SIZE);
			return struct;
		} catch (InvalidDataTypeException e) {
			Msg.error(GsRegister.class, e);
			return null;
		}
	}
	
	private static DataType getGsPrModeCont() {
		StructureDataType struct = new StructureDataType("GsPrModeCont", 0);
		DataType uLong = getU64();
		try {
			struct.addBitField(uLong, 1, "AC", null);
			struct.addBitField(uLong, 63, "pad01", null);
			struct.setExplicitMinimumAlignment(LONG_SIZE);
			return struct;
		} catch (InvalidDataTypeException e) {
			Msg.error(GsRegister.class, e);
			return null;
		}
	}
	
	private static DataType getGsRgbaq() {
		StructureDataType struct = new StructureDataType("GsRGBAQ", 0);
		DataType uInt = UnsignedIntegerDataType.dataType;
		try {
			struct.addBitField(uInt, 8, "R", null);
			struct.addBitField(uInt, 8, "G", null);
			struct.addBitField(uInt, 8, "B", null);
			struct.addBitField(uInt, 8, "A", null);
			struct.add(FloatDataType.dataType, INT_SIZE, "Q", null);
			struct.setExplicitMinimumAlignment(LONG_SIZE);
			return struct;
		} catch (InvalidDataTypeException e) {
			Msg.error(GsRegister.class, e);
			return null;
		}
	}
	
	private static DataType getGsScanMsk() {
		StructureDataType struct = new StructureDataType("GsScanMsk", 0);
		DataType uLong = getU64();
		try {
			struct.addBitField(uLong, 2, "MSK", null);
			struct.addBitField(uLong, 62, "pad02", null);
			struct.setExplicitMinimumAlignment(LONG_SIZE);
			return struct;
		} catch (InvalidDataTypeException e) {
			Msg.error(GsRegister.class, e);
			return null;
		}
	}
	
	private static DataType getGsScissor() {
		StructureDataType struct = new StructureDataType("GsScissor", 0);
		DataType uLong = getU64();
		try {
			struct.addBitField(uLong, 11, "SCAX0", null);
			struct.addBitField(uLong, 5, "pad11", null);
			struct.addBitField(uLong, 11, "SCAX1", null);
			struct.addBitField(uLong, 5, "pad27", null);
			struct.addBitField(uLong, 11, "SCAY0", null);
			struct.addBitField(uLong, 5, "pad43", null);
			struct.addBitField(uLong, 11, "SCAY1", null);
			struct.addBitField(uLong, 5, "pad59", null);
			struct.setExplicitMinimumAlignment(LONG_SIZE);
			return struct;
		} catch (InvalidDataTypeException e) {
			Msg.error(GsRegister.class, e);
			return null;
		}
	}
	
	private static DataType getGsSignal() {
		StructureDataType struct = new StructureDataType("GsSignal", 0);
		struct.add(UnsignedIntegerDataType.dataType, INT_SIZE, "ID", null);
		struct.add(UnsignedIntegerDataType.dataType, INT_SIZE, "IDMSK", null);
		struct.setExplicitMinimumAlignment(LONG_SIZE);
			return struct;
	}
	
	private static DataType getGsSt() {
		StructureDataType struct = new StructureDataType("GsST", 0);
		struct.add(FloatDataType.dataType, INT_SIZE, "S", null);
		struct.add(FloatDataType.dataType, INT_SIZE, "T", null);
		struct.setExplicitMinimumAlignment(LONG_SIZE);
			return struct;
	}
	
	private static DataType getGsTest() {
		StructureDataType struct = new StructureDataType("GsTest", 0);
		DataType uLong = getU64();
		try {
			struct.addBitField(uLong, 1, "ATE", null);
			struct.addBitField(uLong, 3, "ATST", null);
			struct.addBitField(uLong, 8, "AREF", null);
			struct.addBitField(uLong, 2, "AFAIL", null);
			struct.addBitField(uLong, 1, "DATE", null);
			struct.addBitField(uLong, 1, "DATM", null);
			struct.addBitField(uLong, 1, "ZTE", null);
			struct.addBitField(uLong, 2, "ZTST", null);
			struct.addBitField(uLong, 45, "pad19", null);
			struct.setExplicitMinimumAlignment(LONG_SIZE);
			return struct;
		} catch (InvalidDataTypeException e) {
			Msg.error(GsRegister.class, e);
			return null;
		}
	}
	
	private static DataType getGsTex0() {
		StructureDataType struct = new StructureDataType("GsTex0", 0);
		DataType uLong = getU64();
		try {
			struct.addBitField(uLong, 14, "TBP0", null);
			struct.addBitField(uLong, 6, "TBW", null);
			struct.addBitField(uLong, 6, "PSM", null);
			struct.addBitField(uLong, 4, "TW", null);
			struct.addBitField(uLong, 4, "TH", null);
			struct.addBitField(uLong, 1, "TCC", null);
			struct.addBitField(uLong, 2, "TFX", null);
			struct.addBitField(uLong, 14, "CBP", null);
			struct.addBitField(uLong, 4, "CPSM", null);
			struct.addBitField(uLong, 1, "CSM", null);
			struct.addBitField(uLong, 5, "CSA", null);
			struct.addBitField(uLong, 3, "CLD", null);
			struct.setExplicitMinimumAlignment(LONG_SIZE);
			return struct;
		} catch (InvalidDataTypeException e) {
			Msg.error(GsRegister.class, e);
			return null;
		}
	}
	
	private static DataType getGsTex1() {
		StructureDataType struct = new StructureDataType("GsTex1", 0);
		DataType uLong = getU64();
		try {
			struct.addBitField(uLong, 1, "LCM", null);
			struct.addBitField(uLong, 1, "pad01", null);
			struct.addBitField(uLong, 3, "MXL", null);
			struct.addBitField(uLong, 1, "MMAG", null);
			struct.addBitField(uLong, 3, "MMIN", null);
			struct.addBitField(uLong, 1, "MTBA", null);
			struct.addBitField(uLong, 9, "pad10", null);
			struct.addBitField(uLong, 2, "L", null);
			struct.addBitField(uLong, 11, "pad21", null);
			struct.addBitField(uLong, 12, "K", null);
			struct.addBitField(uLong, 20, "pad44", null);
			struct.setExplicitMinimumAlignment(LONG_SIZE);
			return struct;
		} catch (InvalidDataTypeException e) {
			Msg.error(GsRegister.class, e);
			return null;
		}
	}
	
	private static DataType getGsTex2() {
		StructureDataType struct = new StructureDataType("GsTex2", 0);
		DataType uLong = getU64();
		try {
			struct.addBitField(uLong, 20, "pad00", null);
			struct.addBitField(uLong, 6, "PSM", null);
			struct.addBitField(uLong, 11, "pad26", null);
			struct.addBitField(uLong, 14, "CBP", null);
			struct.addBitField(uLong, 4, "CPSM", null);
			struct.addBitField(uLong, 1, "CSM", null);
			struct.addBitField(uLong, 5, "CSA", null);
			struct.addBitField(uLong, 3, "CLD", null);
			struct.setExplicitMinimumAlignment(LONG_SIZE);
			return struct;
		} catch (InvalidDataTypeException e) {
			Msg.error(GsRegister.class, e);
			return null;
		}
	}
	
	private static DataType getGsTexA() {
		StructureDataType struct = new StructureDataType("GsTexA", 0);
		DataType uLong = getU64();
		try {
			struct.addBitField(uLong, 8, "TA0", null);
			struct.addBitField(uLong, 7, "pad08", null);
			struct.addBitField(uLong, 1, "AEM", null);
			struct.addBitField(uLong, 16, "pad16", null);
			struct.addBitField(uLong, 8, "TA1", null);
			struct.addBitField(uLong, 24, "pad40", null);
			struct.setExplicitMinimumAlignment(LONG_SIZE);
			return struct;
		} catch (InvalidDataTypeException e) {
			Msg.error(GsRegister.class, e);
			return null;
		}
	}
	
	private static DataType getGsTexClut() {
		StructureDataType struct = new StructureDataType("GsTexClut", 0);
		DataType uLong = getU64();
		try {
			struct.addBitField(uLong, 6, "CBW", null);
			struct.addBitField(uLong, 6, "COU", null);
			struct.addBitField(uLong, 10, "COV", null);
			struct.addBitField(uLong, 42, "pad22", null);
			struct.setExplicitMinimumAlignment(LONG_SIZE);
			return struct;
		} catch (InvalidDataTypeException e) {
			Msg.error(GsRegister.class, e);
			return null;
		}
	}
	
	private static DataType getGsTexFlush() {
		DataType uLong = getU64();
		return new TypedefDataType("GsTexFlush", uLong);
	}
	
	private static DataType getGsTrxDir() {
		StructureDataType struct = new StructureDataType("GsTrxDir", 0);
		DataType uLong = getU64();
		try {
			struct.addBitField(uLong, 2, "XDR", null);
			struct.addBitField(uLong, 62, "pad02", null);
			struct.setExplicitMinimumAlignment(LONG_SIZE);
			return struct;
		} catch (InvalidDataTypeException e) {
			Msg.error(GsRegister.class, e);
			return null;
		}
	}
	
	private static DataType getGsTrxPos() {
		StructureDataType struct = new StructureDataType("GsTrxPos", 0);
		DataType uLong = getU64();
		try {
			struct.addBitField(uLong, 11, "SSAX", null);
			struct.addBitField(uLong, 5, "pad11", null);
			struct.addBitField(uLong, 11, "SSAY", null);
			struct.addBitField(uLong, 5, "pad27", null);
			struct.addBitField(uLong, 11, "DSAX", null);
			struct.addBitField(uLong, 5, "pad43", null);
			struct.addBitField(uLong, 11, "DSAY", null);
			struct.addBitField(uLong, 2, "DIR", null);
			struct.addBitField(uLong, 3, "pad61", null);
			struct.setExplicitMinimumAlignment(LONG_SIZE);
			return struct;
		} catch (InvalidDataTypeException e) {
			Msg.error(GsRegister.class, e);
			return null;
		}
	}
	
	private static DataType getGsTrxReg() {
		StructureDataType struct = new StructureDataType(GS_TRX_REG, 0);
		DataType uLong = getU64();
		try {
			struct.addBitField(uLong, 12, "RRW", null);
			struct.addBitField(uLong, 20, "pad12", null);
			struct.addBitField(uLong, 12, "RRH", null);
			struct.addBitField(uLong, 20, "pad44", null);
			struct.setExplicitMinimumAlignment(LONG_SIZE);
			return struct;
		} catch (InvalidDataTypeException e) {
			Msg.error(GsRegister.class, e);
			return null;
		}
	}
	
	private static DataType getGsUv() {
		StructureDataType struct = new StructureDataType("GsUV", 0);
		DataType uLong = getU64();
		try {
			struct.addBitField(uLong, 14, "U", null);
			struct.addBitField(uLong, 2, "pad14", null);
			struct.addBitField(uLong, 14, "V", null);
			struct.addBitField(uLong, 34, "pad30", null);
			struct.setExplicitMinimumAlignment(LONG_SIZE);
			return struct;
		} catch (InvalidDataTypeException e) {
			Msg.error(GsRegister.class, e);
			return null;
		}
	}
	
	private static DataType getGsXyoffset() {
		StructureDataType struct = new StructureDataType("GsXYOffset", 0);
		DataType uLong = getU64();
		try {
			struct.addBitField(uLong, 16, "OFX", null);
			struct.addBitField(uLong, 16, "pad16", null);
			struct.addBitField(uLong, 16, "OFY", null);
			struct.addBitField(uLong, 16, "pad48", null);
			struct.setExplicitMinimumAlignment(LONG_SIZE);
			return struct;
		} catch (InvalidDataTypeException e) {
			Msg.error(GsRegister.class, e);
			return null;
		}
	}
	
	private static DataType getGsXYZ() {
		StructureDataType struct = new StructureDataType("GsXYZ", 0);
		DataType uLong = getU64();
		try {
			struct.addBitField(uLong, 16, "X", null);
			struct.addBitField(uLong, 16, "Y", null);
			struct.addBitField(uLong, 32, "Z", null);
			struct.setExplicitMinimumAlignment(LONG_SIZE);
			return struct;
		} catch (InvalidDataTypeException e) {
			Msg.error(GsRegister.class, e);
			return null;
		}
	}
	
	private static DataType getGsXYZF() {
		StructureDataType struct = new StructureDataType("GsXYZF", 0);
		DataType uLong = getU64();
		try {
			struct.addBitField(uLong, 16, "X", null);
			struct.addBitField(uLong, 16, "Y", null);
			struct.addBitField(uLong, 24, "Z", null);
			struct.addBitField(uLong, 8, "F", null);
			struct.setExplicitMinimumAlignment(LONG_SIZE);
			return struct;
		} catch (InvalidDataTypeException e) {
			Msg.error(GsRegister.class, e);
			return null;
		}
	}
	
	private static DataType getGsZbuf() {
		StructureDataType struct = new StructureDataType("GsZBuf", 0);
		DataType uLong = getU64();
		try {
			struct.addBitField(uLong, 9, "ZBP", null);
			struct.addBitField(uLong, 15, "pad09", null);
			struct.addBitField(uLong, 4, "PSM", null);
			struct.addBitField(uLong, 4, "pad28", null);
			struct.addBitField(uLong, 1, "ZMSK", null);
			struct.addBitField(uLong, 31, "pad33", null);
			struct.setExplicitMinimumAlignment(LONG_SIZE);
			return struct;
		} catch (InvalidDataTypeException e) {
			Msg.error(GsRegister.class, e);
			return null;
		}
	}

	private static DataType getU64() {
		return new TypedefDataType("u64", QWordDataType.dataType);
	}
}
