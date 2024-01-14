package ghidra.emotionengine.data;

import java.awt.image.DataBuffer;
import java.awt.image.IndexColorModel;
import java.nio.ByteBuffer;

class GsClut {

	private ByteBuffer buf;
	private final GsPSM psm;

	GsClut(byte[] data, GsPSM psm) {
		this.buf = ByteBuffer.wrap(data);
		this.psm = psm;
	}

	IndexColorModel getClutModel() {
		int clutSize;
		int bitDepth;
		switch (psm) {
			// unpack clut data to 8888 RGBA if necessary
			case PSMCT16:
				// unpack
				// TODO
				// hey dummy ColorModel color = new ColorModel(16);
				clutSize = 16;
				short[] colors = new short[buf.array().length >> 1];
				//buf.order(ByteOrder.LITTLE_ENDIAN);
				buf.asShortBuffer().get(colors);
				int[] pixels = new int[colors.length];
				for (int i = 0; i < colors.length; i++) {
					pixels[i] = (int) colors[i];
				}
				return new IndexColorModel(
					4, clutSize, pixels, 0, DataBuffer.TYPE_BYTE, null);
			case PSMCT16S:
				// unpack
				bitDepth = 8;
				clutSize = 256;
				break;
			default:
				bitDepth = 8;
				clutSize = 256;
				break;
		}
		return new IndexColorModel(bitDepth, clutSize, buf.array(), 0, false);
	}

}
