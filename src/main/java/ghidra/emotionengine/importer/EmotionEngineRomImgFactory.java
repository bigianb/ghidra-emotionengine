package ghidra.emotionengine.importer;

import java.io.IOException;
import java.util.Set;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.formats.gfilesystem.FSRL;
import ghidra.formats.gfilesystem.FSRLRoot;
import ghidra.formats.gfilesystem.FSUtilities;
import ghidra.formats.gfilesystem.FileSystemService;
import ghidra.formats.gfilesystem.GFileSystem;
import ghidra.formats.gfilesystem.factory.GFileSystemFactoryByteProvider;
import ghidra.formats.gfilesystem.factory.GFileSystemProbeByteProvider;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import static ghidra.emotionengine.importer.EmotionEngineRomImgFileSystem.MAX_HEADER_OFFSET;

public class EmotionEngineRomImgFactory
		implements GFileSystemFactoryByteProvider<EmotionEngineRomImgFileSystem>,
		GFileSystemProbeByteProvider {

	private static final Set<String> EXTENSION = Set.of(".bin", ".img");
	private static final String[] HEADER_NAMES = new String[] {"RESET", "ROMDIR", "EXTINFO"};

	private static final int BLOCK_SIZE = 0x10;

	protected static String getNullTerminatedString(byte[] bytes) {
		for (int i = 0; i < bytes.length; i++) {
			if (bytes[i] == 0) {
				return new String(bytes, 0, i);
			}
		}
		return new String(bytes);
	}

	protected static int getHeaderOffset(ByteProvider byteProvider) throws IOException {
		BinaryReader reader = new BinaryReader(byteProvider, false);
		return getHeaderOffset(reader);
	}
	
	protected static int getHeaderOffset(BinaryReader reader) throws IOException {
		for (long i = reader.getPointerIndex(); i < MAX_HEADER_OFFSET; i += BLOCK_SIZE) {
			reader.setPointerIndex(i);
			if (reader.peekNextByte() == 'R') {
				if (reader.readNextAsciiString().equals(HEADER_NAMES[0])) {
					return (int) i;
				}
			}
		}
		return -1;
	}

	public boolean probeStartBytes(BinaryReader reader) throws IOException {
		int offset = getHeaderOffset(reader);
		if (offset == -1) {
			return false;
		}
		reader.setPointerIndex(offset);
		for (String header : HEADER_NAMES) {
			if (!reader.readNextAsciiString().equals(header)) {
				return false;
			}
			offset += BLOCK_SIZE;
			reader.setPointerIndex(offset);
		}
		return true;
	}

	@Override
	public GFileSystem create(FSRLRoot targetFSRL, ByteProvider byteProvider, FileSystemService fsService,
			TaskMonitor monitor) throws IOException, CancelledException {
		EmotionEngineRomImgFileSystem fs = new EmotionEngineRomImgFileSystem(targetFSRL, byteProvider);
		fs.mount(monitor);
		return fs;
	}

	@Override
	public boolean probe(ByteProvider byteProvider, FileSystemService fsService, TaskMonitor monitor)
			throws IOException, CancelledException {
		FSRL containerFSRL = byteProvider.getFSRL();
		if (containerFSRL == null) {
			return false;
		}
		String filename = containerFSRL.getName();
		String ext = FSUtilities.getExtension(filename, 1);
		if (ext != null && EXTENSION.contains(ext.toLowerCase())) {
			BinaryReader reader = new BinaryReader(byteProvider, false);
			return probeStartBytes(reader);
		}
		return false;
	}
			
}
