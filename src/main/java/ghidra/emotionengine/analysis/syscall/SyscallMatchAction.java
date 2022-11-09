package ghidra.emotionengine.analysis.syscall;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.bytesearch.*;
import ghidra.xml.XmlPullParser;

final class SyscallMatchAction implements MatchAction {

	static final String BIOS = "BIOS";
	static final DittedBitSequence BYTE_SEQUENCE =
		new DittedBitSequence(
			"0x.. 0x.. 0x03 0x24 0x0C 0x00 0x00 0x00 0x08 0x00 0xE0 0x03 0x00 0x00 0x00 0x00");

	private final MessageLog log;

	SyscallMatchAction(MessageLog log) {
		this.log = log;
	}

	@Override
	public void apply(Program program, Address addr, Match match) {
		try {
			short key = program.getMemory().getShort(addr);
			SyscallInfo info = SyscallTable.getSyscall(key);
			if (info == null) {
				BookmarkManager man = program.getBookmarkManager();
				man.setBookmark(
					addr, BookmarkType.WARNING, BookmarkType.WARNING, "Unknown Syscall");
				info = new SyscallInfo("syscall_"+Short.toString(key), key);
			}
			createSyscall(program, info, addr);
		} catch (Exception e) {
			log.appendException(e);
		}
	}

	private static Library getBios(Program program) {
		ExternalManager manager = program.getExternalManager();
		return manager.getExternalLibrary(BIOS);
	}

	private static void createSyscall(Program program, SyscallInfo info, Address address)
			throws Exception {
		Listing listing = program.getListing();
		Library bios = getBios(program);
		ExternalManager manager = program.getExternalManager();
		ExternalLocation syscall =
			manager.addExtFunction(bios, info.getName(), null, SourceType.IMPORTED, true);
		if (listing.getInstructionAt(address) == null) {
			DisassembleCommand cmd = new DisassembleCommand(address, null, true);

			// this is always a background thread so it's ok to directly invoke
			cmd.applyTo(program);
		}
		Function function = listing.getFunctionAt(address);
		if (function == null) {
			CreateFunctionCmd cmd =
				new CreateFunctionCmd(null, address, null, SourceType.IMPORTED);

			// same as above
			cmd.applyTo(program);
			function = cmd.getFunction();
		}
		function.setThunkedFunction(syscall.createFunction());
	}

	@Override
	public void restoreXml(XmlPullParser parser) {
		throw new UnsupportedOperationException();
	}

	Pattern getPattern() {
		return new Pattern(BYTE_SEQUENCE, 0, new PostRule[0], new MatchAction[]{ this });
	}

}
