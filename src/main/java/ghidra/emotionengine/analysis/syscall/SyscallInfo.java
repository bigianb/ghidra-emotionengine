package ghidra.emotionengine.analysis.syscall;

final class SyscallInfo {

	private final String name;
	private final short number;

	SyscallInfo(String name, short number) {
		this.name = name != null ? name : "syscall_"+Short.toString(number);
		this.number = number;
	}

	String getName() {
		return name;
	}

	short getNumber() {
		return number;
	}
}
