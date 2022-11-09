package ghidra.emotionengine.demangler;

import ghidra.app.util.NamespaceUtils;
import ghidra.app.util.demangler.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.task.TaskMonitor;

abstract class DemangledMetrowerksSpecial extends UserDemangledObject {

	private final String prefix;
	private final DemangledDataType type;

	protected DemangledMetrowerksSpecial(String mangled, String prefix, DemangledDataType type) {
		super(mangled, prefix+" for "+type.getNamespaceString());
		setNamespace(type);
		this.prefix = prefix;
		this.type = type;
	}

	@Override
	public boolean applyTo(Program program, Address address, DemanglerOptions options,
			TaskMonitor monitor) throws Exception {
		if (super.applyTo(program, address, options, monitor)) {
			SymbolTable table = program.getSymbolTable();
			String namespace = type.getNamespaceString().replaceAll(" ", "");
			Namespace ns = NamespaceUtils.createNamespaceHierarchy(
				namespace, program.getGlobalNamespace(), program, SourceType.ANALYSIS);
			table.createLabel(address, prefix, ns, SourceType.ANALYSIS);
			return true;
		}
		return false;
	}

	@Override
	public final String getSignature(boolean format) {
		return prefix+" for "+type.getSignature();
	}
}
