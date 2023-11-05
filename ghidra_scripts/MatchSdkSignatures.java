// Given the contents of an "SDK signature library", matches labels to functions
// in the program with known binary signatures.
// This script does not actually apply the label, and is primarily for testing
// and prototyping.
//@category ghidra-ps2sdk

import java.io.File;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.ps2sdk.format.*;
import ghidra.ps2sdk.match.SdkSignatureLibraryMatches;
import ghidra.ps2sdk.match.SdkSignatureMatch;
import ghidra.ps2sdk.match.SdkSignatureMatcher;
import ghidra.ps2sdk.match.SdkSignatureMatcherOptions;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.DummyCancellableTaskMonitor;
import ghidra.util.task.TaskMonitor;

public class MatchSdkSignatures extends GhidraScript {
	private static final String MATCH_MSG_FMT = "Matched %s ==> %s";
	public void run() throws Exception {
		//
		// Get the SDK signature library data.
		//
		File libFile = askFile("Select an SDK signature library JSON file.", "Select");
		SdkLibrary library = SdkLibraryParser.deserialize(libFile);

		//
		// Match signatures against all selected functions. (The default matcher options are used.)
		//
		SdkSignatureMatcher matcher = new SdkSignatureMatcher(new SdkSignatureMatcherOptions());
		TaskMonitor monitor = new DummyCancellableTaskMonitor();
		println("Hashing functions in the current selection...");
		SdkSignatureLibraryMatches matchLib = matcher.match(library, currentProgram, currentSelection, monitor);
		List<SdkSignatureMatch> matches = matchLib.getMatches();
		println("Number of matches: " + matches.size());

		//
		// Apply matched labels.
		//
		int transId = currentProgram.startTransaction("Applying SDK function labels");
		for(SdkSignatureMatch match : matches) {
			List<Function> matchedFuncs = match.getMatchedFunctions();
			SdkFunction matchSig = match.getMatchedSignature();

			if(matchedFuncs.size() > 1) {
				println(String.format("Multiple matches for %s:", matchSig.getLabel()));
				for(Function f : matchedFuncs) {
					println("  " + String.format(MATCH_MSG_FMT, f.getName(), matchSig.getLabel()));
				}
			} else {
				println(String.format(MATCH_MSG_FMT, matchedFuncs.get(0).getName(), matchSig.getLabel()));
			}
		}
		currentProgram.endTransaction(transId, true);

		println("Done.");
	}
}
