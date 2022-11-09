package ghidra.emotionengine;

import ghidra.program.model.data.Array;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.BooleanDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.TypedefDataType;
import ghidra.program.model.data.Union;
import ghidra.program.model.data.UnionDataType;
import ghidra.util.Msg;

import static ghidra.app.util.bin.StructConverter.BYTE;
import static ghidra.app.util.bin.StructConverter.DWORD;
import static ghidra.app.util.bin.StructConverter.WORD;

// dbg = ghidra.emotionengine.EmotionEngine_Mdebug.getEcoffDebugInfo()

public class EmotionEngine_Mdebug {

    private static final CategoryPath MDEBUG_PATH = new CategoryPath(CategoryPath.ROOT, "mdebug");

    private static final DataType BOOL = BooleanDataType.dataType;
    private static final TypeDef RFD = new TypedefDataType(MDEBUG_PATH, "rfd_ext", DWORD);
    private static final TypeDef LINE = new TypedefDataType(MDEBUG_PATH, "line_ext", DWORD);

    private EmotionEngine_Mdebug() {
    }

    public static void addAll(DataTypeManager dtm) {
        dtm.resolve(getEcoffDebugInfo(), DataTypeConflictHandler.REPLACE_HANDLER);
        dtm.resolve(getHDRR(), DataTypeConflictHandler.REPLACE_HANDLER);
        dtm.resolve(getFDR(), DataTypeConflictHandler.REPLACE_HANDLER);
        dtm.resolve(getPdrExt(), DataTypeConflictHandler.REPLACE_HANDLER);
        dtm.resolve(getPdr64Ext(), DataTypeConflictHandler.REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD_HANDLER);
        dtm.resolve(getRpdrExt(), DataTypeConflictHandler.REPLACE_HANDLER);
        dtm.resolve(getSymExt(), DataTypeConflictHandler.REPLACE_HANDLER);
        dtm.resolve(getExtExt(), DataTypeConflictHandler.REPLACE_HANDLER);
        dtm.resolve(getTirExt(), DataTypeConflictHandler.REPLACE_HANDLER);
        dtm.resolve(getRndxExt(), DataTypeConflictHandler.REPLACE_HANDLER);
        dtm.resolve(getDnrExt(), DataTypeConflictHandler.REPLACE_HANDLER);
        dtm.resolve(getAuxExt(), DataTypeConflictHandler.REPLACE_HANDLER);
        dtm.resolve(getOptExt(), DataTypeConflictHandler.REPLACE_HANDLER);
        dtm.resolve(getAouthdrExt(), DataTypeConflictHandler.REPLACE_HANDLER);
    }

    public static Structure getEcoffDebugInfo() {
        Structure struct = new StructureDataType(MDEBUG_PATH, "ecoff_debug_info", 0);
        struct.add(getHDRR(), "symbolic_header", "The swapped ECOFF symbolic header");
        struct.add(LINE, "line", null);
        struct.add(DWORD, "external_dnr", "struct dnr_ext");
        struct.add(DWORD, "external_pdr", "struct pdr_ext");
        struct.add(DWORD, "external_sym", "struct sym_ext");
        struct.add(DWORD, "external_opt", "struct opt_ext");
        struct.add(DWORD, "external_aux", null);
        struct.add(DWORD, "ss", null);
        struct.add(DWORD, "ssext", null);
        struct.add(DWORD, "external_fdr", "struct fdr_ext");
        struct.add(DWORD, "external_rfd", "struct rfd_ext");
        struct.add(DWORD, "external_ext", "struct ext_ext");
        struct.add(DWORD, "ssext_end", null);
        struct.add(DWORD, "external_ext_end", null);
        struct.add(DWORD, "ifdmap", null);
        struct.add(DWORD, "fdr", "The swapped FDR information");
        return struct;
    }

    // done
    public static Structure getHDRR() {
        Structure struct = new StructureDataType(MDEBUG_PATH, "HDRR", 0);
        struct.add(WORD, "magic", "(0x7009)");
        struct.add(WORD, "vstamp", "version stamp");
        struct.add(DWORD, "ilineMax", "number of line number entries");
        struct.add(DWORD, "cbLine", "number of bytes for line number entries");
        struct.add(DWORD, "cbLineOffset", "offset to start of line number entries");
        struct.add(DWORD, "idnMax", "max index into dense number table");
        struct.add(DWORD, "cbDnOffset", "offset to start dense number table");
        struct.add(DWORD, "ipdMax", "number of procedures");
        struct.add(DWORD, "cbPdOffset", "offset to procedure descriptor table");
        struct.add(DWORD, "isymMax", "number of local symbols");
        struct.add(DWORD, "cbSymOffset", "offset to start of local symbols");
        struct.add(DWORD, "ioptMax", "max index into optimization symbol entries");
        struct.add(DWORD, "cbOptOffset", "offset to optimization symbol entries");
        struct.add(DWORD, "iauxMax", "number of auxillary symbol entries");
        struct.add(DWORD, "cbAuxOffset", "offset to start of auxillary symbol entries");
        struct.add(DWORD, "issMax", "max index into local strings");
        struct.add(DWORD, "cbSsOffset", "offset to start of local strings");
        struct.add(DWORD, "issExtMax", "max index into external strings");
        struct.add(DWORD, "cbSsExtOffset", "offset to start of external strings");
        struct.add(DWORD, "ifdMax", "number of file descriptor entries");
        struct.add(DWORD, "cbFdOffset", "offset to file descriptor table");
        struct.add(DWORD, "crfd", "number of relative file descriptor entries");
        struct.add(DWORD, "cbRfdOffset", "offset to relative file descriptor table");
        struct.add(DWORD, "iextMax", "max index into external symbols");
        struct.add(DWORD, "cbExtOffset", "offset to start of external symbol entries");
        return struct;
    }

    // done
    public static Structure getFDR() {
        Structure struct = new StructureDataType(MDEBUG_PATH, "FDR", 0);
        struct.add(DWORD, "adr", "memory address of beginning of file");
        struct.add(DWORD, "rss", "file name (of source, if known)");
        struct.add(DWORD, "issBase", "file's string space");
        struct.add(DWORD, "cbSs", "number of bytes in the ss");
        struct.add(DWORD, "isymBase", "beginning of symbols");
        struct.add(DWORD, "csym", "count file's of symbols");
        struct.add(DWORD, "ilineBase", "file's line symbols");
        struct.add(DWORD, "cline", "count of file's line symbols");
        struct.add(DWORD, "ioptBase", "file's optimization entries");
        struct.add(DWORD, "copt", "count of file's optimization entries");
        struct.add(WORD, "ipdFirst", "start of procedures for this file");
        struct.add(WORD, "cpd", "count of procedures for this file");
        struct.add(DWORD, "iauxBase", "file's auxiliary entries");
        struct.add(DWORD, "caux", "count of file's auxiliary entries");
        struct.add(DWORD, "rfdBase", "index into the file indirect table");
        struct.add(DWORD, "crfd", "count file indirect entries");
        try {
            struct.addBitField(BYTE, 5,
                "lang", "language for this file");
            struct.addBitField(BOOL, 1,
                "fMerge", "whether this file can be merged");
            struct.addBitField(BOOL, 1,
                "fReadin", "true if it was read in (not just created)");
            struct.addBitField(BOOL, 1,
                "fBigendian", "if set, was compiled on big endian machine");
            struct.addBitField(BYTE, 2,
                "glevel", "level this file was compiled with");
            struct.addBitField(DWORD, 22,
                "reserved", null);
        } catch (InvalidDataTypeException e) {
            Msg.error(EmotionEngine_Mdebug.class, e);
        }
        struct.add(DWORD, "cbLineOffset", "byte offset from header for this file ln's");
        struct.add(DWORD, "cbLine", "size of lines for this file");
		struct.setToMachineAligned();
		struct.setPackingEnabled(true);
        return struct;
    }

    public static Structure getPdrExt() {
        Structure struct = new StructureDataType(MDEBUG_PATH, "pdr_ext", 0);
        struct.add(DWORD, "adr", "memory address of start of procedure");
        struct.add(DWORD, "isym", "start of local symbol entries");
        struct.add(DWORD, "iline", "start of line number entries");
        struct.add(DWORD, "regmask", "save register mask");
        struct.add(DWORD, "regoffset", "save register offset");
        struct.add(DWORD, "iopt", "start of optimization symbol entries");
        struct.add(DWORD, "fregmask", "save floating point register mask");
        struct.add(DWORD, "fregoffset", "save floating point register offset");
        struct.add(DWORD, "frameoffset", "frame size");
        struct.add(WORD, "framereg", "frame pointer register");
        struct.add(WORD, "pcreg", "offset or reg of return pc");
        struct.add(LINE, "lnLow", "lowest line in the procedure");
        struct.add(LINE, "lnHigh", "highest line in the procedure");
        struct.add(DWORD, "cbLineOffset", "byte offset for this procedure from the fd base");
        return struct;
    }

    public static Structure getPdr64Ext() {
        Structure struct = new StructureDataType(MDEBUG_PATH, "pdr_ext", 0);
        for (DataTypeComponent comp : getPdrExt().getComponents()) {
            struct.add(comp.getDataType(), comp.getFieldName(), comp.getComment());
        }
        try {
            struct.addBitField(BYTE, 8, "gp_prologue", "byte size of GP prologue");
            struct.addBitField(BOOL, 1, "gp_used", "true if the procedure uses GP");
            struct.addBitField(BOOL, 1, "reg_frame", "true if register frame procedure");
            struct.addBitField(BOOL, 1, "prof", "true if compiled with -pg");
            struct.addBitField(WORD, 13, "reserved", null);
            struct.addBitField(BYTE, 8, "localoff", "offset of local variables from vfp");
        } catch (InvalidDataTypeException e) {
            Msg.error(EmotionEngine_Mdebug.class, e);
        }
		struct.setToMachineAligned();
		struct.setPackingEnabled(true);
        return struct;
    }

    public static Structure getRpdrExt() {
        Structure struct = new StructureDataType(MDEBUG_PATH, "rpdr_ext", 0);
        struct.add(DWORD, "adr", "memory address of start of procedure");
        struct.add(DWORD, "regmask", "save register mask");
        struct.add(DWORD, "regoffset", "save register offset");
        struct.add(DWORD, "fregmask", "save floating point register mask");
        struct.add(DWORD, "fregoffset", "save floating point register offset");
        struct.add(DWORD, "frameoffset", "frame size");
        struct.add(WORD, "framereg", "frame pointer register");
        struct.add(WORD, "pcreg", "offset or reg of return pc");
        struct.add(DWORD, "irpss", "index into the runtime string table");
        struct.add(DWORD, "reserved", null);
        struct.add(DWORD, "exception_info", "pointer to exception array");
        return struct;
    }

    public static Structure getSymExt() {
        Structure struct = new StructureDataType(MDEBUG_PATH, "sym_ext", 0);
        struct.add(DWORD, "iss", "index into String Space of name");
        struct.add(DWORD, "value", "value of symbol");
        try {
            struct.addBitField(BYTE, 6, "st", "symbol type");
            struct.addBitField(BYTE, 5, "sc", "storage class - text, data, etc");
            struct.addBitField(BYTE, 1, "reserved", null);
            struct.addBitField(DWORD, 20, "index", "index into sym/aux table");
        } catch (InvalidDataTypeException e) {
            Msg.error(EmotionEngine_Mdebug.class, e);
        }
		struct.setToMachineAligned();
		struct.setPackingEnabled(true);
        return struct;
    }

    public static Structure getExtExt() {
        Structure struct = new StructureDataType(MDEBUG_PATH, "ext_ext", 0);
        try {
            struct.addBitField(BOOL, 1, "jmptbk", "symbol is a jump table entry for shlibs");
            struct.addBitField(BOOL, 1, "cobol_main", "symbol is a cobol main procedure");
            struct.addBitField(BOOL, 1, "weakext", "symbol is weak external");
            struct.addBitField(BYTE, 1, "reserved", null);
        } catch (InvalidDataTypeException e) {
            Msg.error(EmotionEngine_Mdebug.class, e);
        }
        struct.add(WORD, "ifd", "where the iss and index fields point into");
        struct.add(getSymExt(), "asym", "symbol for the external");
		struct.setToMachineAligned();
		struct.setPackingEnabled(true);
        return struct;
    }

    public static Structure getTirExt() {
        Structure struct = new StructureDataType(MDEBUG_PATH, "tir_ext", 0);
        try {
            struct.addBitField(BOOL, 1, "fBitfield", "set if bit width is specified");
            struct.addBitField(BOOL, 1, "continued", "indicates additional TQ info in next AUX");
            struct.addBitField(BYTE, 6, "bt", "basic type");
            struct.addBitField(BYTE, 4, "tq4", null);
            struct.addBitField(BYTE, 4, "tq5", null);
            struct.addBitField(BYTE, 4, "tq0", null);
            struct.addBitField(BYTE, 4, "tq1", null);
            struct.addBitField(BYTE, 4, "tq2", null);
            struct.addBitField(BYTE, 4, "tq3", null);
        } catch (InvalidDataTypeException e) {
            Msg.error(EmotionEngine_Mdebug.class, e);
        }
		struct.setToMachineAligned();
		struct.setPackingEnabled(true);
        return struct;
    }

    public static Structure getRndxExt() {
        Structure struct = new StructureDataType(MDEBUG_PATH, "rndx_ext", 0);
        try {
            struct.addBitField(RFD, 12, "rfd", "index into the file indirect table");
            struct.addBitField(DWORD, 20, "index", "index int sym/aux/iss tables");
        } catch (InvalidDataTypeException e) {
            Msg.error(EmotionEngine_Mdebug.class, e);
        }
		struct.setToMachineAligned();
		struct.setPackingEnabled(true);
        return struct;
    }

    public static Structure getDnrExt() {
        Structure struct = new StructureDataType(MDEBUG_PATH, "dnr_ext", 0);
        struct.add(RFD, "rfd", "index into the file table");
        struct.add(DWORD, "index", "index int sym/aux/iss tables");
        return struct;
    }

    public static Union getAuxExt() {
        Union union = new UnionDataType(MDEBUG_PATH, "aux_ext");
        union.add(getTirExt(), "ti", "type information record");
        union.add(getRndxExt(), "rndx", "relative index into symbol table");
        union.add(DWORD, "dnLow", "low dimension");
        union.add(DWORD, "dnHigh", "high dimension");
        union.add(DWORD, "isym", "symbol table index (end of proc)");
        union.add(DWORD, "iss", "index into string space (not used)");
        union.add(DWORD, "width", "width for non-default sized struc fields");
        union.add(DWORD, "count", "count of ranges for variant arm");
        return union;
    }

    public static Structure getOptExt() {
        Structure struct = new StructureDataType(MDEBUG_PATH, "opt_ext", 0);
        try {
            struct.addBitField(BYTE, 8, "ot", "optimization type");
            struct.addBitField(DWORD, 24, "value", "address where we are moving it to");
        } catch (InvalidDataTypeException e) {
            Msg.error(EmotionEngine_Mdebug.class, e);
        }
        struct.add(getRndxExt(), "rndx", "points to a symbol or opt entry");
        struct.add(DWORD, "offset", "relative offset this occured");
		struct.setToMachineAligned();
		struct.setPackingEnabled(true);
        return struct;
    }

    public static Structure getAouthdrExt() {
        Structure struct = new StructureDataType(MDEBUG_PATH, "aouthdr_ext", 0);
        Array array = new ArrayDataType(DWORD, 4, DWORD.getLength());
        struct.add(WORD, "magic", "type of file");
        struct.add(WORD, "vstamp", "version stamp");
        struct.add(DWORD, "tsize", "text size in bytes, padded to FW bdry");
        struct.add(DWORD, "dsize", "initialized data");
        struct.add(DWORD, "bsize", "uninitialized data");
        struct.add(DWORD, "entry", "entry pt");
        struct.add(DWORD, "text_start", "base of text used for this file");
        struct.add(DWORD, "data_start", "base of data used for this file");
        struct.add(DWORD, "bss_start", "base of bss used for this file");
        struct.add(DWORD, "gprmask", null);
        struct.add(array, "cprmask", null);
        struct.add(DWORD, "gp_value", "value for gp register");
        return struct;
    }
}
