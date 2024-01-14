package ghidra.emotionengine.analysis;

import java.util.ArrayList;
import java.util.List;

import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.emotionengine.iop.IopModule;
import ghidra.emotionengine.iop.IopModuleUtil;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.TerminatedStringDataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.ExternalManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.util.StringUtilities;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

public final class EmotionEngineIrxAnalyzer extends AbstractEmotionEngineAnalyzer {

	private static final int EXTENSION_LENGTH = 4;
	private static final String NAME = "Irx Analyzer";
	private static final String DESCRIPTION =
		"Locates IRX module imports and adds them to the SymbolTree IMPORTS";

	public EmotionEngineIrxAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.DATA_ANALYZER);
	}
	
	@Override
	public boolean canAnalyze(Program program) {
		// disable for now
		return false;
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor,
			MessageLog log) throws CancelledException {
		init(program, monitor, log);
		List<Address> addresses = new ArrayList<>(findStrings(".img"));
		addresses.addAll(findStrings(".IMG"));
		addresses.addAll(findStrings(".irx"));
		addresses.addAll(findStrings(".IRX"));
		monitor.initialize(addresses.size());
		monitor.setMessage("Adding module imports");
		for (Address address : addresses) {
			monitor.checkCanceled();
			try {
				handleImport(address);
			} catch (Exception e) {
				log.appendException(e);
			}
			monitor.incrementProgress(1);
		}
		return true;
	}
	
	private void handleImport(Address address) throws Exception {
		String module = getModuleName(address);
		if (module.isBlank()) {
			return;
		}
		if (!SymbolUtilities.containsInvalidChars(module)) {
			// don't create a module for a log message
			createExternalModule(module);
		}
	}

	private String getModuleName(Address address) throws Exception {
		Listing listing = program.getListing();
		Data data = listing.getDataContaining(address);
		if (data == null || data.getValueClass() != String.class) {
			data = getStringData(address);
		}
		String name = StringUtilities.getLastWord((String) data.getValue(), "\\").split(";")[0];
		return name.toUpperCase();
	}

	private Data getStringData(Address address) throws Exception {
		Listing listing = program.getListing();
		Address end = address.add(EXTENSION_LENGTH);
		MemBuffer buf = new DumbMemBufferImpl(program.getMemory(), address);
		int offset = 0;
		while (true) {
			char b = (char) buf.getByte(offset);
			if (!StringUtilities.isAsciiChar(b)) {
				break;
			}
			offset--;
		}
		address = address.add(offset);
		listing.clearCodeUnits(address, end, true);
		return listing.createData(address, TerminatedStringDataType.dataType);
	}

	private void createExternalModule(String module) {
		module = module.replaceAll(".IRX", "").toLowerCase();
		ExternalManager manager = program.getExternalManager();
		if (!manager.contains(module)) {
			try {
				IopModule irx = IopModuleUtil.getIopModule(module);
				Library library = manager.addExternalLibraryName(module, SourceType.IMPORTED);
				if (irx == null) {
					return;
				}
				for (String function : irx.getFunctions()) {
					manager.addExtFunction(library, function, null, SourceType.IMPORTED, true);
				}
			} catch (DuplicateNameException | InvalidInputException e) {
				// cant happen
				throw new AssertException(e);
			}
		}
	}
}
