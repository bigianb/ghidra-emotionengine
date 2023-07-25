//Export function definitions in json
//@author Ian
//@category Functions
//@keybinding 
//@menupath 
//@toolbar 

import java.io.File;
import java.io.FileWriter;

import com.google.gson.*;
import com.google.gson.stream.JsonWriter;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.util.*;
import ghidra.program.model.reloc.*;
import ghidra.program.model.data.*;
import ghidra.program.model.block.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;

public class ExportFunctionDefs extends GhidraScript {

	private static final String NAME = "name";
	private static final String ENTRY = "entry";
	private static final String ADDRESS = "address";

	@Override
	public void run() throws Exception {

		Gson gson = new GsonBuilder().setPrettyPrinting().create();

		File outputFile = askFile("Please Select Output File", "Choose");
		JsonWriter jsonWriter = new JsonWriter(new FileWriter(outputFile));
		jsonWriter.beginObject();

		jsonWriter.name("functions");
		jsonWriter.beginArray();
		Listing listing = currentProgram.getListing();
		FunctionIterator iter = listing.getFunctions(true);
		while (iter.hasNext() && !monitor.isCancelled()) {
			Function f = iter.next();

			String name = f.getName();
			if (!name.startsWith("FUN_")){
				Address entry = f.getEntryPoint();
				JsonObject json = new JsonObject();
				json.addProperty(NAME, name);
				json.addProperty(ENTRY, entry.toString());

				gson.toJson(json, jsonWriter);
			}
		}
		jsonWriter.endArray();

		jsonWriter.name("symbols");
		jsonWriter.beginArray();

		SymbolTable symbolTable = currentProgram.getSymbolTable();
		SymbolIterator symbolIterator = symbolTable.getDefinedSymbols();
		while (symbolIterator.hasNext() && !monitor.isCancelled()) {
			Symbol symbol = symbolIterator.next();
			SymbolType type = symbol.getSymbolType();
			if (!symbol.isDynamic() && symbol.isGlobal() && type == SymbolType.LABEL){
				String name = symbol.getName();
				Address address = symbol.getAddress();
				AddressSpace addressSpace = address.getAddressSpace();
if (addressSpace.getType() == AddressSpace.TYPE_RAM){
				JsonObject json = new JsonObject();
				json.addProperty(NAME, name);
				json.addProperty(ADDRESS, address.toString());

				gson.toJson(json, jsonWriter);
}
			}
		}
		jsonWriter.endArray();
		jsonWriter.endObject();
		jsonWriter.close();

		println("Wrote functions to " + outputFile);
	}

}
