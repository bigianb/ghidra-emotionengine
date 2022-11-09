package ghidra.emotionengine;

import java.io.IOException;
import java.math.BigInteger;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

import ghidra.app.cmd.data.CreateStringCmd;
import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.elf.ElfException;
import ghidra.app.util.bin.format.elf.ElfHeader;
import ghidra.app.util.bin.format.elf.extend.MIPS_ElfExtension;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.*;
import ghidra.emotionengine.demangler.MetrowerksDemangler;
import ghidra.emotionengine.iop.IopModule;
import ghidra.emotionengine.iop.IopModuleUtil;
import ghidra.framework.model.DomainFolder;
import ghidra.program.model.address.*;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.PropertyMapManager;
import ghidra.program.util.ProgramMemoryUtil;
import ghidra.util.Msg;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

public class EmotionEngineLoader extends ElfLoader {

	private static final String RELOCATION_TRANSACTION_MESSAGE = "Resetting Relocatons";
	public final static String EE_PROCESSOR_NAME = "MIPS-R5900";
	protected final static String IOP_PROCESSOR_NAME = "MIPS-R3000";
	private static final Set<String> TARGET_PROCESSORS = Set.of(EE_PROCESSOR_NAME, IOP_PROCESSOR_NAME);

	private static final int DEFAULT_HEAP_SIZE = 1024;

	private static final byte[] IMPORT_MAGIC = {0, 0, (byte) 0xe0, 0x41};
	private static final byte[] EXPORT_MAGIC = {0, 0, (byte) 0xc0, 0x41};
	private static final String DEFAULT_FUNCTION_NAME = "Ordinal_";
	private static final int INSTRUCTION_ALIGNMENT = 4;
	private static final int INSTRUCTION_PAIR_SIZE = 8;
	private static final int NAME_ORDINAL = INSTRUCTION_ALIGNMENT;

	private static final String REL_PREFIX = ".rel";
	private static final String MAIN = "main";
	private static final String MW_CATS = ".mwcats";

	private static final String NAME = "Emotion Engine Loader";
	private static final byte[] JUMP_RETURN = {8, 0, (byte) 0xe0, 3, 0, 0, 0, 0};

	private static final Set<String> IGNORED_MESSAGES = Collections.unmodifiableSet(
		Set.of(
			"Skipping segment[0, null] included by section .iopmod",
			"There were too many messages to display.",
			" "));

	private static final Pattern EXTERNAL_RELOCATION_MESSAGE =
		Pattern.compile("Unable to perform relocation\\:.*Block is non-existent");

	private static final String TRUNCATION_MESSAGE = "messages have been truncated.";
	private static final String EXTERNAL_FUNCTION_MESSAGE =
		"All functions in the external block \"%s\" have been replaced with a jump return.";

	public EmotionEngineLoader() {
		super();
	}

	public static boolean canLoad(Program program) {
		return TARGET_PROCESSORS.contains(program.getLanguage().getProcessor().toString());
	}

	@Override
	public LoaderTier getTier() {
		return LoaderTier.SPECIALIZED_TARGET_LOADER;
	}

	@Override
	public int getTierPriority() {
		return super.getTierPriority()-1;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		try {
			ElfHeader elf = new ElfHeader(provider, (String s) -> Msg.info(this, s));
			List<QueryResult> results =
				QueryOpinionService.query(getName(), elf.getMachineName(), elf.getFlags());
			for (QueryResult result : results) {
				Processor processor = result.pair.getLanguage().getProcessor();
				if (TARGET_PROCESSORS.contains(processor.toString())) {
					loadSpecs.add(new LoadSpec(this, 0, result));
				}
			}
		} catch (ElfException e) {
			// not a problem, it's not an elf
		}

		return loadSpecs;
	}

	@Override
	public void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log)
			throws IOException, CancelledException {
		super.load(provider, loadSpec, options, program, monitor, log);
		String[] messages = log.toString().split("\n");
		log.clear();
		for (String message : messages) {
			monitor.checkCanceled();
			if (!IGNORED_MESSAGES.contains(message)) {
				if (!message.contains(TRUNCATION_MESSAGE)) {
					Matcher matcher = EXTERNAL_RELOCATION_MESSAGE.matcher(message);
					if (!matcher.matches()) {
						log.appendMsg(message);
					}
				}
			}
		}
		setDemanglerFormat(program, log);
	}

	private void setDemanglerFormat(Program program, MessageLog log) {
		boolean isMw = false;
		for (MemoryBlock block : program.getMemory().getBlocks()) {
			if (block.getName().startsWith(MW_CATS)) {
				isMw = true;
				break;
			}
			if (block.getName().equals(".comment")) {
				CreateStringCmd cmd = new CreateStringCmd(block.getStart());
				if (cmd.applyTo(program)) {
					Listing listing = program.getListing();
					Data data = listing.getDataAt(block.getStart());
					if (data != null && data.getValueClass() == String.class) {
						isMw = ((String) data.getValue()).startsWith("MW MIPS C Compiler");
						break;
					}
				}
			}
		}

		if (isMw) {
			PropertyMapManager manager = program.getUsrPropertyManager();
			try {
				manager.createVoidPropertyMap(MetrowerksDemangler.METROWERKS_DEMANGLER_PROPERTY);
			} catch (DuplicateNameException e) {
				throw new AssertException(e);
			}
		}
	}

	@Override
	protected void postLoadProgramFixups(List<Program> importedPrograms, DomainFolder importFolder,
			List<Option> options, MessageLog messageLog, TaskMonitor monitor)
			throws CancelledException, IOException {
		for (Program program : importedPrograms) {
			monitor.checkCanceled();
			int id = program.startTransaction(RELOCATION_TRANSACTION_MESSAGE);
			// TODO setup heap memory block if applicable
			// default size is 1024
			// Main Memory is 256 MB, Extended Main Memory is 1 GB
			processElf(program, messageLog, monitor);
			Memory mem = program.getMemory();
			Listing listing = program.getListing();
			ExternalManager manager = program.getExternalManager();
			for (String libName : manager.getExternalLibraryNames()) {
				if (libName.equals(".text")) {
					continue;
				}
				ExternalLocationIterator iter = manager.getExternalLocations(libName);
				Iterable<ExternalLocation> locations = () -> iter;
				List<ExternalLocation> locList = StreamSupport
					.stream(locations.spliterator(), false)
					.collect(Collectors.toList());
				if (!locList.isEmpty()) {
					messageLog.appendMsg(String.format(EXTERNAL_FUNCTION_MESSAGE, libName));
					monitor.initialize(locList.size());
					monitor.setMessage("Fixing External Functions in "+libName);
					for (ExternalLocation loc : locList) {
						monitor.checkCanceled();
						try {
							if (loc.getAddress() != null) {
								if (!mem.getBlock(loc.getAddress()).isInitialized()) {
									MemoryBlock block = mem.getBlock(loc.getAddress());
									mem.convertToInitialized(block, (byte) 0);
								}
								Data data = listing.getDataContaining(loc.getAddress());
								if (data != null) {
									listing.clearCodeUnits(
										data.getAddress(), data.getAddress(), false);
								}
								mem.setBytes(loc.getAddress(), JUMP_RETURN);
							}
						} catch (Exception e) {
							messageLog.appendException(e);
						}
						monitor.incrementProgress(1);
					}
				}
			}
			program.endTransaction(id, true);
			id = program.startTransaction("Setting up heap");
			SymbolTable table = program.getSymbolTable();
			List<Symbol> symbols = table.getGlobalSymbols(MIPS_ElfExtension.MIPS_GP_VALUE_SYMBOL);
			if (symbols.size() == 1) {
				MemoryBlock block = mem.getBlock(symbols.get(0).getAddress());
				if (block == null) {
					try {
						mem.createUninitializedBlock(
							"ram", symbols.get(0).getAddress(), DEFAULT_HEAP_SIZE, false);
					} catch (Exception e) {
						throw new AssertException(e);
					}
				}
			}
			program.endTransaction(id, true);
		}
		super.postLoadProgramFixups(importedPrograms, importFolder, options, messageLog, monitor);
	}

	@Override
	public String getName() {
		return NAME;
	}

	private boolean isEE(Program program) {
		return program.getLanguage().getProcessor().toString().equals(EE_PROCESSOR_NAME);
	}

	public static void setMicroMode(Program program, MemoryBlock block) {
		Register microMode = program.getRegister("microMode");
		if (block != null) {
			try {
				program.getProgramContext().setValue(microMode, block.getStart(),
					block.getEnd(), BigInteger.ONE);
			}
			catch (ContextChangeException e) {
				// ignore since should not be instructions at time of import
			}
		}
	}

	public void processElf(Program program, MessageLog log, TaskMonitor monitor)
			throws CancelledException {
				try {
					if (isEE(program)) {
						doEEModuleImports(program, monitor);
					} else {
						doModuleImports(program, monitor);
						doModuleExports(program, monitor);
					}
				} catch (CancelledException e) {
					throw e;
				} catch (Exception e) {
					log.appendException(e);
				}
		}

	private void doModuleImports(Program program, TaskMonitor monitor)
			throws Exception  {
		AddressSetView moduleSet = getModuleAddressSet(program, monitor, IMPORT_MAGIC);
		Memory mem = program.getMemory();
		Listing listing = program.getListing();
		DataType dt = IopModuleUtil.getModuleStruct(program);
		ExternalManager manager = program.getExternalManager();
		monitor.setMessage("Applying Module Imports");
		monitor.initialize(moduleSet.getNumAddresses());
		for (AddressRange range : moduleSet.getAddressRanges()) {
			monitor.checkCanceled();
			Address address = range.getMinAddress();
			Data data = listing.createData(address, dt);
			String moduleName = (String) data.getComponent(NAME_ORDINAL).getValue();
			Library library;
			if (manager.contains(moduleName)) {
			   library = manager.getExternalLibrary(moduleName);
			} else {
				library = manager.addExternalLibraryName(moduleName, SourceType.IMPORTED);
			}
			IopModule module = IopModuleUtil.getIopModule(moduleName);
			address = address.add(data.getLength());
			while (mem.getInt(address) != 0) {
				monitor.checkCanceled();
				int key = (int) (mem.getLong(address.add(INSTRUCTION_ALIGNMENT)) & 0xffff);
				String functionName;
				if (module != null && module.containsKey(key)) {
					functionName = module.getFunction(key);
				} else {
					functionName = DEFAULT_FUNCTION_NAME+Long.toString(key);
				}
				createExternalFunctionLinkage(library, functionName, address);
				address = address.add(INSTRUCTION_PAIR_SIZE);
			}
			monitor.incrementProgress(1);
		}
	}

	private void createExternalFunctionLinkage(Library library, String name, Address addr)
			throws Exception {
		Program program = library.getSymbol().getProgram();
		ExternalManager manager = program.getExternalManager();
		FunctionManager fManager = program.getFunctionManager();
		Function fun = fManager.getFunctionAt(addr);
		if (fun == null) {
			fun = fManager.createFunction(name, addr, new AddressSet(addr), SourceType.IMPORTED);
		}
		ExternalLocation loc = manager.addExtFunction(
			library, name, null, SourceType.IMPORTED, true);
		fun.setThunkedFunction(loc.createFunction());
	}

	private List<MemoryBlock> getExternalBlocks(Program program, TaskMonitor monitor)
		throws CancelledException{
			Memory mem = program.getMemory();
			List<MemoryBlock> rels = ProgramMemoryUtil.getMemoryBlocksStartingWithName(
				program, mem, REL_PREFIX, monitor);
			ArrayList<MemoryBlock> result = new ArrayList<>(rels.size());
			for (MemoryBlock block : rels) {
				monitor.checkCanceled();
				String name = block.getName().substring(REL_PREFIX.length());
				if (!name.equals(MAIN)) {
					MemoryBlock subBlock = mem.getBlock(name);
					if (subBlock != null) {
						result.add(subBlock);
					}
				}
			}
			result.trimToSize();
			return result;
	}

	private void doEEModuleImports(Program program, TaskMonitor monitor)
		throws Exception {
		ExternalManager manager = program.getExternalManager();
		FunctionManager fManager = program.getFunctionManager();
		List<MemoryBlock> externalBlocks = getExternalBlocks(program, monitor);
		for (MemoryBlock block : externalBlocks) {
			monitor.checkCanceled();
			if (block.getName().equals(".text")) {
				continue;
			}
			Library library;
			if (!manager.contains(block.getName())) {
				library = manager.addExternalLibraryName(
					block.getName(), SourceType.IMPORTED);
			} else {
				library = manager.getExternalLibrary(block.getName());
			}
			AddressSet set = new AddressSet(block.getStart(), block.getEnd());
			List<Function> funList = StreamSupport
				.stream(fManager.getFunctions(set, true).spliterator(), false)
				.collect(Collectors.toList());
			monitor.initialize(funList.size());
			monitor.setMessage("Processing External Block "+block.getName());
			for (Function fun : funList) {
				monitor.checkCanceled();
				String fName = fun.getName();
				Address entry = fun.getEntryPoint();
				//fManager.removeFunction(entry);
				//mem.setBytes(entry, JUMP_RETURN);
				//elfLoadHelper.createExternalFunctionLinkage(
				//	fName, entry, null);
				ExternalLocation loc = manager.addExtFunction(
					library, fName, entry, SourceType.IMPORTED, true);
				fun.setThunkedFunction(loc.createFunction());
				monitor.incrementProgress(1);
			}
		}
	}

	private void doModuleExports(Program program, TaskMonitor monitor) throws Exception {
		AddressSetView moduleSet = getModuleAddressSet(program, monitor, EXPORT_MAGIC);
		DataType dt = IopModuleUtil.getModuleStruct(program);
		DataType pointer = PointerDataType.dataType;
		SymbolTable table = program.getSymbolTable();
		FunctionManager manager = program.getFunctionManager();
		Listing listing = program.getListing();
		monitor.setMessage("Applying Module Exports");
		monitor.initialize(moduleSet.getNumAddressRanges());
		for (AddressRange range : moduleSet.getAddressRanges()) {
			monitor.checkCanceled();
			Address address = range.getMinAddress();
			Address end = address.add(dt.getLength());
			listing.clearCodeUnits(address, end, true, monitor);
			Data data = listing.createData(address, dt);
			String moduleName = (String) data.getComponent(NAME_ORDINAL).getValue();
			IopModule module = IopModuleUtil.getIopModule(moduleName);
			Address tableStart = address.add(data.getLength());
			listing.createData(tableStart, pointer);
			address = tableStart.add(pointer.getLength());
			Set<Address> processed = new HashSet<>();
			int i = 1;
			while (true) {
				monitor.checkCanceled();
				if (processed.contains(address)) {
					break;
				}
				String name;
				if (module != null && module.containsKey(i)) {
					name = module.getFunction(i);
				} else {
					name = DEFAULT_FUNCTION_NAME+Long.toString(i);
				}
				listing.clearCodeUnits(address, address.add(4), true);
				Data pointerData = listing.createData(address, pointer);
				Address functionAddress = (Address) pointerData.getValue();
				processed.add(functionAddress);
				Function function = manager.getFunctionAt(functionAddress);
				if (function == null) {
					try {
						function = manager.createFunction(
							name, functionAddress,
							new AddressSet(functionAddress), SourceType.IMPORTED);
					} catch (IllegalArgumentException e) {
						// defined data exists here. End of exports.
						break;
					}
				}
				table.addExternalEntryPoint(functionAddress);
				address = address.add(pointer.getLength());
				i++;
			}
		}
	}

	private AddressSetView getModuleAddressSet(Program program, TaskMonitor monitor, byte[] magic)
		throws CancelledException {
			AddressSet set = new AddressSet();
			Memory mem = program.getMemory();
			for (AddressRange range : mem.getExecuteSet().getAddressRanges()) {
				monitor.checkCanceled();
				Address address = range.getMinAddress();
				while (true) {
					monitor.checkCanceled();
					address = mem.findBytes(
						address, range.getMaxAddress(), magic, null, true, monitor);
					if (address == null) {
						break;
					}
					if (address.getOffset() % INSTRUCTION_ALIGNMENT == 0) {
						set.add(address);
					}
					address = address.next();
				}
			}
			return set;
	}
}
