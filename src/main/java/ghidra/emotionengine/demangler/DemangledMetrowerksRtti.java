package ghidra.emotionengine.demangler;

import ghidra.app.util.demangler.DemangledDataType;
import ghidra.app.util.demangler.DemanglerOptions;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

final class DemangledMetrowerksRtti extends DemangledMetrowerksSpecial {

	private static final DataType dataType = getDataType();

	public DemangledMetrowerksRtti(String mangled, DemangledDataType type) {
		super(mangled, "typeinfo", type);
	}

	@Override
	public boolean applyTo(Program program, Address address, DemanglerOptions options,
			TaskMonitor monitor) throws Exception {
		if (super.applyTo(program, address, options, monitor)) {
			DataUtilities.createData(
				program, address, dataType, -1, false, ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
			return true;
		}
		return false;
	}

	private static DataType getDataType() {
		CategoryPath path = new CategoryPath(CategoryPath.ROOT, "std/typeinfo");
		Structure struct = new StructureDataType(path, "type_info", 0);
		PointerDataType tname = new PointerDataType(CharDataType.dataType);
		PointerDataType tbase = new PointerDataType(VoidDataType.dataType);
		struct.add(tname, "tname", null);
		struct.add(tbase, "tbase", null);
		struct.setToMachineAligned();
		struct.setPackingEnabled(true);
		return struct;
	}
}
