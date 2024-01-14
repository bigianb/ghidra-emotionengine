package ghidra.emotionengine.iop;

import java.util.*;

import ghidra.framework.Application;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.ShortDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;
import ghidra.xml.XmlPullParserFactory;

import org.xml.sax.helpers.DefaultHandler;

import generic.jar.ResourceFile;

public class IopModuleUtil {

	private static final String MODULE_NAME = "Module";
	private static final String MAGIC = "MAGIC";
	private static final String MODE = "mode";
	private static final String NAME = "name";
	private static final String VERSION = "version";
	private static final String NEXT_TABLE = "next";
	private static final String IRX_MODULES = "irx_modules.xml";
	private static final Map<String, IopModule> IRX_MAP = getModules();

	private IopModuleUtil() {}
	
	public static Map<String, IopModule> getModules() {
		try {
			Map<String, IopModule> modules = new HashMap<>();
			ResourceFile file = Application.getModuleDataFile(IRX_MODULES);
			XmlPullParser parser = XmlPullParserFactory.create(file, new DefaultHandler(), true);
			try {
				XmlElement header = parser.next();
				if (header.getName().equals("modules")) {
					while(parser.hasNext()) {
						XmlElement next = parser.peek();
						if (next != null && next.getName().equals("module")) {
							IopModule module = new IopModule(parser);
							modules.put(module.getName(), module);
							parser.next();
						} else {
							parser.next();
						}
					}
				}
			} finally {
				parser.dispose();
			}
			return modules;
		} catch (Exception e) {
			Msg.error(IopModuleUtil.class, e);
		}
		return Collections.emptyMap();
	}

	public static DataType getModuleStruct(Program program) {
		DataTypeManager dtm = program.getDataTypeManager();
		StructureDataType struct = new StructureDataType(MODULE_NAME, 0, dtm);
		ArrayDataType magicArray = new ArrayDataType(ByteDataType.dataType, 4, 1, dtm);
		ArrayDataType nameArray = new ArrayDataType(CharDataType.dataType, 8, 1, dtm);
		DataType pointer = dtm.getPointer(struct, program.getDefaultPointerSize());
		struct.add(magicArray, magicArray.getLength(), MAGIC, null);
		struct.add(pointer, pointer.getLength(), NEXT_TABLE, null);
		struct.add(ShortDataType.dataType, 2, VERSION, null);
		struct.add(ShortDataType.dataType, 2, MODE, null);
		struct.add(nameArray, nameArray.getLength(), NAME, null);
		return dtm.resolve(struct, DataTypeConflictHandler.REPLACE_HANDLER);
	}

	public static IopModule getIopModule(String name) {
		return IRX_MAP.get(name);
	}

}
