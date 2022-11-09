package ghidra.emotionengine.importer;

import ghidra.app.util.recognizer.Recognizer;

public class EmotionEngineMwOverlayRecognizer implements Recognizer {
	
	@Override
	public int numberOfBytesRequired() {
		return 3;
	}

	@Override
	public String recognize(byte[] bytes) {
		if (bytes.length >= numberOfBytesRequired()) {
            if (bytes[0] == (byte) 'M' &&
                bytes[1] == (byte) 'W' &&
                bytes[2] == (byte) 'o') {
                return "File appears to be a MW Overlay";
            }
        }
        return null;
	}

	@Override
	public int getPriority() {
		return 100;
	}
	
}
