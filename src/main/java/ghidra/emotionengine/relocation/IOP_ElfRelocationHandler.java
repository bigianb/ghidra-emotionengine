/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *	  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.emotionengine.relocation;

import ghidra.app.util.bin.format.elf.*;
import ghidra.app.util.bin.format.elf.relocation.ElfRelocationContext;
import ghidra.app.util.bin.format.elf.relocation.MIPS_ElfRelocationConstants;
import ghidra.app.util.bin.format.elf.relocation.MIPS_ElfRelocationHandler;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.*;
import ghidra.program.model.reloc.Relocation.Status;
import ghidra.program.model.reloc.RelocationResult;
import ghidra.util.classfinder.ExtensionPointProperties;

import static ghidra.emotionengine.EmotionEngine_ElfExtension.ET_IRX2;

@ExtensionPointProperties(priority = 2)
public class IOP_ElfRelocationHandler extends MIPS_ElfRelocationHandler {

	private static final int R_MIPS_MHI16 = 0xfa;
	private static final int R_MIPS_ADDEND = 0xfb;

	private static final String ILLEGAL_RELOCATION_MESSAGE =
		"Illegal R_MIPS_MHI16 Relocation in ET_IRX2 IopModule";
	private static final String ILLEGAL_MHI16_MESSAGE =
		"R_MIPS_MHI16 not followed by R_MIPS_ADDEND";

	private static final int LOW_MASK = 0xffff;
	private static final int HIGH_MASK = 0xffff0000;
	
	private static final int MACHINE_MIPS_R3000 = 8;

	@Override
	public boolean canRelocate(ElfHeader elf) {
		return super.canRelocate(elf) && (elf.e_machine() == MACHINE_MIPS_R3000);
	}

	@Override
	public RelocationResult relocate(ElfRelocationContext elfRelocationContext, ElfRelocation relocation,
			Address relocationAddress) throws MemoryAccessException {
		Program program = elfRelocationContext.getProgram();
		Memory memory = program.getMemory();
		MessageLog log = elfRelocationContext.getLog();
		BookmarkManager bMan = program.getBookmarkManager();
		ElfSymbol elfSymbol = elfRelocationContext.getSymbol(relocation.getSymbolIndex());

		String symbolName = elfSymbol.getNameAsString();

		int base = (int) elfRelocationContext.getImageBaseWordAdjustmentOffset();
		int value = 0;
		int newValue = 0;
		int oldValue = memory.getInt(relocationAddress);
		switch(relocation.getType()) {
			case MIPS_ElfRelocationConstants.R_MIPS_16:
				value = (oldValue << 16) >> 16;
				value += base;
				newValue = oldValue & HIGH_MASK;
				newValue |= value & LOW_MASK;
				break;
			case MIPS_ElfRelocationConstants.R_MIPS_32:
				newValue = oldValue+base;
				break;
			case MIPS_ElfRelocationConstants.R_MIPS_26:
				value = (oldValue & MIPS_ElfRelocationConstants.MIPS_LOW26) << 2;
				value |= (oldValue & 0xf0000000);
				value += base;
				newValue = oldValue & 0xfc000000;
				newValue |= (value << 4) >> 6;
				break;
			case R_MIPS_MHI16:
				if (elfRelocationContext.getElfHeader().e_type() == ET_IRX2) {
					markAsError(program, relocationAddress, relocation.getType(),
						symbolName, ILLEGAL_RELOCATION_MESSAGE, log);
					return RelocationResult.FAILURE;
				}
				ElfRelocation nextReloc = getNextRelocation(
					elfRelocationContext, relocation);
				if (nextReloc == null || nextReloc.getType() != R_MIPS_ADDEND) {
					markAsError(program, relocationAddress, relocation.getType(),
						symbolName, ILLEGAL_MHI16_MESSAGE, log);
					return RelocationResult.FAILURE;
				}
				value =  (int) nextReloc.getOffset()+base;
				value = (((value >> 15) + 1) >> 1) & LOW_MASK;
				int offset = 0;
				Address currentAddress = relocationAddress;
				int byteLength = 0;
				do {
					oldValue = memory.getInt(currentAddress);
					offset = ((oldValue & LOW_MASK) << 16) >> 14;
					newValue = oldValue & HIGH_MASK;
					newValue |= value;
					memory.setInt(currentAddress, newValue);
					currentAddress = currentAddress.add(offset);
					byteLength += 4;
				} while(offset != 0);
				return new RelocationResult(Status.APPLIED, byteLength);
			
			
			
			default:
				String msg = String.format("Unexpected relocation type %d", relocation.getType());
				bMan.setBookmark(relocationAddress, BookmarkType.ERROR, BookmarkType.ERROR, msg);
			case MIPS_ElfRelocationConstants.R_MIPS_NONE:
			case MIPS_ElfRelocationConstants.R_MIPS_HI16:
			case MIPS_ElfRelocationConstants.R_MIPS_LO16:
			case MIPS_ElfRelocationConstants.R_MIPS_GPREL16:
				return RelocationResult.UNSUPPORTED;
		}

		memory.setInt(relocationAddress, newValue);

		return new RelocationResult(Status.APPLIED, 4);
	}

	private ElfRelocation getNextRelocation(ElfRelocationContext context,
		ElfRelocation relocation) {
			ElfHeader elf = context.getElfHeader();
			int index = relocation.getRelocationIndex();
			for (ElfRelocationTable table : elf.getRelocationTables()) {
				ElfRelocation[] relocations = table.getRelocations();
				if (index < relocations.length) {
					if (relocations[index].equals(relocation)) {
						return relocations[index+1];
					}
				}
			}
			return null;
		}

}