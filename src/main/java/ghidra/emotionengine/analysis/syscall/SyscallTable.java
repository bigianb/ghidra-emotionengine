package ghidra.emotionengine.analysis.syscall;

import java.util.Collections;
import java.util.Map;
import java.util.TreeMap;

import ghidra.framework.Application;
import ghidra.util.Msg;
import ghidra.util.NumericUtilities;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;
import ghidra.xml.XmlPullParserFactory;

import org.xml.sax.helpers.DefaultHandler;

import generic.jar.ResourceFile;

final class SyscallTable {
	private static final String SYSCALL_FILE = "syscalls.xml";
	private static final Map<Short, String> SYSCALL_TABLE = buildSyscallTable();

	private static Map<Short, String> buildSyscallTable() {
		try {
			ResourceFile file = Application.getModuleDataFile(SYSCALL_FILE);
			XmlPullParser parser = XmlPullParserFactory.create(file, new DefaultHandler(), true);
			try {
				XmlElement header = parser.next();
				if (header.getName().equals("syscalls")) {
					Map<Short, String> table = new TreeMap<>();
					while (parser.hasNext()) {
						XmlElement syscall = parser.next();
						if (syscall.getName().equals("syscall")) {
							Short id =
								(short) NumericUtilities.parseHexLong(syscall.getAttribute("id"));
							table.put(id, syscall.getAttribute("name"));
							parser.next();
						}
					}
					return table;
				}
			} finally {
				parser.dispose();
			}
		} catch (Exception e) {
			Msg.error(SyscallTable.class, e);
		}
		return Collections.emptyMap();
	}

	static SyscallInfo getSyscall(short key) {
		return new SyscallInfo(SYSCALL_TABLE.get(key), key);
	}

}
