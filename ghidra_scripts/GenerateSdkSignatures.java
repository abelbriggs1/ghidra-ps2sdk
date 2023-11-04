// Generates hashed function signatures for all selected functions and writes them
// to am "SDK library" JSON file.
//@category ghidra-ps2sdk

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import com.google.gson.JsonParseException;
import ghidra.app.script.GhidraScript;
import ghidra.ps2sdk.format.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.util.task.DummyCancellableTaskMonitor;
import ghidra.util.task.TaskMonitor;

public class GenerateSdkSignatures extends GhidraScript {
	private static final String SDK_FILE_FMT = "%s.json";

	public void run() throws Exception {
		//
		// Verify that the current selection contains functions.
		//
		FunctionManager manager = currentProgram.getFunctionManager();
		FunctionIterator funcs = manager.getFunctions(currentSelection, true);
		if (funcs == null || !funcs.hasNext()) {
			println("No functions in the current selection. Exiting.");
			return;
		}

		//
		// Support merging into an existing library database - otherwise, get the library's
		// name and future file location.
		//
		boolean merge = askYesNo("Merge", "Merge signatures into an existing SDK library signature file?");
		SdkLibrary library;
		File libFile;
		if (merge) {
			libFile = askFile("Select SDK Library File", "Select");
			try {
				library = SdkLibraryParser.deserialize(libFile);
			} catch (IOException | JsonParseException e) {
				printerr("Couldn't parse the existing JSON file!");
				throw e;
			}
		} else {
			String libName = askString("SDK Library Name", "Enter a name for the SDK library.");
			File libDir = askDirectory("Select a directory to save the file.", "Select");
			libFile = new File(libDir, String.format(SDK_FILE_FMT, libName));
			library = new SdkLibrary(libName, new ArrayList<SdkFunction>());
		}

		//
		// Collect signatures from the current selection.
		// Instead of collecting directly to `SdkFunction`s, we collect to a map of `label -> signature`
		// first because we want to overwrite any existing signatures with the same label.
		//
		println("Collecting signatures from the current selection...");
		List<SdkFunction> sdkFuncs = library.getFunctions();
		// LinkedHashMap is used to preserve insertion order.
		Map<String, SdkSignature> funcMap = sdkFuncs.stream().collect(
				Collectors.toMap(
						SdkFunction::getLabel,
						SdkFunction::getSignature,
						(key1, key2) -> { throw new IllegalStateException("Duplicate labels"); },
						LinkedHashMap::new)
		);
		TaskMonitor dummyMon = new DummyCancellableTaskMonitor();
		for (Function func : funcs) {
			println("Collecting signature of " + func.getName());
			funcMap.put(func.getName(), SdkSignature.fromFunction(func, dummyMon));
		}
		sdkFuncs.clear();
		sdkFuncs.addAll(funcMap.entrySet().stream().map(
				entry -> new SdkFunction(entry.getKey(), entry.getValue())
		).collect(Collectors.toList()));

		//
		// Serialize signatures to file.
		//
		println("Serializing library to file...");
		SdkLibraryParser.serialize(libFile, library);

		println("Done.");
	}
}
