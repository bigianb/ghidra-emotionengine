package ghidra.emotionengine.importer;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.ByteProviderInputStream;
import ghidra.app.util.bin.ByteProviderWrapper;
import ghidra.formats.gfilesystem.FSRLRoot;
import ghidra.formats.gfilesystem.FileSystemIndexHelper;
import ghidra.formats.gfilesystem.FileSystemRefManager;
import ghidra.formats.gfilesystem.GFile;
import ghidra.formats.gfilesystem.GFileSystem;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import static ghidra.emotionengine.importer.EmotionEngineRomImgFactory.getHeaderOffset;

@FileSystemInfo(type = "img", description = "Iop Rom Image", priority = FileSystemInfo.PRIORITY_LOW, factory = EmotionEngineRomImgFactory.class)
public class EmotionEngineRomImgFileSystem implements GFileSystem {

	private FSRLRoot fsrl;
	private ByteProvider provider;
	private static final byte BLOCK_SIZE = 0x10;
	private FileSystemIndexHelper<RomDirMetaData> helper;
	private FileSystemRefManager refManager = new FileSystemRefManager(this);
	protected static final int MAX_NAME_LENGTH = 10;
	private boolean isClosed = false;

	protected static final int MAX_HEADER_OFFSET = 0x50000;
	private static final String FILE_SEPARATOR = "-";

	public EmotionEngineRomImgFileSystem(FSRLRoot fsrl, ByteProvider provider) {
		this.fsrl = fsrl;
		this.helper = new FileSystemIndexHelper<>(this, fsrl.getFS());
		this.provider = provider;
	}

	protected void mount(TaskMonitor monitor) throws IOException, CancelledException {
		int offset = getHeaderOffset(provider);
		BinaryReader reader = new BinaryReader(provider, true);
		reader.setPointerIndex(offset);
		int index = 0;
		while (true) {
			monitor.checkCanceled();
			if (reader.peekNextByte() == 0) {
				break;
			}
			RomDirMetaData meta = new RomDirMetaData(reader);
			if (meta.name.equals(FILE_SEPARATOR)) {
				meta.name = meta.name + Integer.toString(index);
			}
			reader.align(BLOCK_SIZE);
			helper.storeFile(meta.name, index++, false, meta.size, meta);
		}
		reader.setPointerIndex(reader.getPointerIndex()+BLOCK_SIZE);
		for (int i = 0; i < index; i++) {
			monitor.checkCanceled();
			GFile file = helper.getFileByIndex(i);
			RomDirMetaData meta = helper.getMetadata(file);
			if (meta.extsize == 0) {
				// EXTINFO has no extinfo :p
				continue;
			}
			meta.fillExtInfo(reader);
		}
		// seek back to the start of romdir
		reader.setPointerIndex(offset);
		for (int i = 0; i < index; i++) {
			monitor.checkCanceled();
			reader.align(BLOCK_SIZE);
			GFile file = helper.getFileByIndex(i);
			RomDirMetaData meta = helper.getMetadata(file);
			meta.offset = reader.getPointerIndex();
			reader.setPointerIndex(meta.offset + meta.size);
		}
	}

	@Override
	public void close() throws IOException {
		if (isClosed) {
			throw new IOException(getName()+" is closed.");
		}
		refManager.onClose();
		provider.close();
		isClosed = true;
	}

	@Override
	public String getName() {
		return provider.getName();
	}

	@Override
	public FSRLRoot getFSRL() {
		return fsrl;
	}

	@Override
	public boolean isClosed() {
		return isClosed;
	}

	@Override
	public FileSystemRefManager getRefManager() {
		return refManager;
	}

	@Override
	public GFile lookup(String path) throws IOException {
		return helper.lookup(path);
	}

	@Override
	public InputStream getInputStream(GFile file, TaskMonitor monitor)
			throws IOException, CancelledException {
		RomDirMetaData meta = helper.getMetadata(file);
		if (meta == null) {
			throw new IOException("Unknown file " + file);
		}
		ByteProvider wrapped = new ByteProviderWrapper(provider, meta.offset, meta.size);
		return new ByteProviderInputStream(wrapped);
	}

	@Override
	public List<GFile> getListing(GFile directory) throws IOException {
		return helper.getListing(directory);
	}
	
	@Override
	public ByteProvider getByteProvider(GFile file, TaskMonitor monitor) throws IOException, CancelledException {
		RomDirMetaData meta = helper.getMetadata(file);
		if (meta == null) {
			return null;
		}
		return new ByteProviderWrapper(provider, meta.offset, meta.size, file.getFSRL());
	}

	@SuppressWarnings("unused")
	private static class RomDirMetaData {
		static final byte EXT_HEADER_SIZE = 4;
		static final byte SIZE_OFFSET = 0xc;
		static final byte DATE = 1;
		static final byte VERSION = 2;
		static final byte DESCRIPTION = 3;
		static final byte NULL = 0x7f;

		String name;
		String description;
		byte flags;
		int date;
		short version;
		long offset;
		int extsize;
		int size;

		RomDirMetaData(BinaryReader reader) throws IOException {
			long pos = reader.getPointerIndex();
			name = reader.readNextAsciiString();
			reader.setPointerIndex(pos + MAX_NAME_LENGTH);
			extsize = reader.readNextUnsignedShort();
			size = reader.readNextInt();
		}

		void fillExtInfo(BinaryReader reader) throws IOException {
			while (extsize > 0) {
				short value = reader.readNextShort();
				byte metaSize = reader.readNextByte();
				byte id = reader.readNextByte();
				extsize -= EXT_HEADER_SIZE;
				switch (id) {
					case DATE:
						date = reader.readNextInt();
						flags |= 1;
						break;
					case VERSION:
						version = value;
						flags |= 2;
						break;
					case DESCRIPTION:
						description = new String(reader.readNextByteArray(metaSize));
						flags |= 4;
						break;
					case NULL:
						flags |= 8;
						break;
					default:
						break;
				}
				extsize -= metaSize;
			}
		}
	}

}
