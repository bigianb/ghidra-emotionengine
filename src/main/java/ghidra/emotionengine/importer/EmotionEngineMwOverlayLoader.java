package ghidra.emotionengine.importer;

import java.io.IOException;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.BinaryLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public final class EmotionEngineMwOverlayLoader extends BinaryLoader {

	private static final LanguageCompilerSpecPair SPEC_PAIR =
		new LanguageCompilerSpecPair("r5900:LE:32:default", "default");

	private static final EmotionEngineMwOverlayRecognizer RECOGNIZER =
		new EmotionEngineMwOverlayRecognizer();

	@Override
	public String getName() {
		return "MW Overlay Loader";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		String result =
			RECOGNIZER.recognize(provider.readBytes(0, RECOGNIZER.numberOfBytesRequired()));

		if (result != null) {
			return List.of(new LoadSpec(this, 0, SPEC_PAIR, true));
		}
		return Collections.emptySet();
	}

	@Override
	protected boolean loadProgramInto(ByteProvider provider, LoadSpec loadSpec,
			List<Option> options, MessageLog log, Program prog, TaskMonitor monitor)
			throws IOException, CancelledException {
		String result =
			RECOGNIZER.recognize(provider.readBytes(0, RECOGNIZER.numberOfBytesRequired()));
		if (result != null) {
			try {
				MwOverlayLoaderHelper helper = new MwOverlayLoaderHelper(provider, prog, monitor);
				helper.loadOverlay();
				return true;
			} catch (Exception e) {
				e.printStackTrace();
				log.appendException(e);
			}
		}
		return false;
	}
}
