package ghidra.emotionengine.data;

enum GsPSM {
	PSMCT32((byte) 0),
	PSMCT24((byte) 1),
	PSMCT16((byte) 2),
	PSMCT16S((byte) 0xa),
	PSMT8((byte) 0x13),
	PSMT4((byte) 0x14) ,
	PSMT8H((byte) 0x1b),
	PSMT4HL((byte) 0x24),
	PSMT4HH((byte) 0x2c),
	PSMZ32((byte) 0x30),
	PSMZ24((byte) 0x31),
	PSMZ16((byte) 0x32),
	PSMZ16S((byte) 0x3a);

	private byte value;

	GsPSM(byte value) {
		this.value = value;
	}

	static GsPSM getGsPSM(byte value) {
		for (GsPSM psm : GsPSM.values()) {
			if (psm.value == value) {
				return psm;
			}
		}
		return null;
	}

}