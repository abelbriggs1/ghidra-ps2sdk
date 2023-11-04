package ghidra.ps2sdk.match;

import com.google.common.collect.Lists;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.MessageLog;
import ghidra.ps2sdk.format.SdkFunction;
import ghidra.ps2sdk.format.SdkLibrary;
import ghidra.ps2sdk.format.SdkSignature;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

/**
 * Common signature matcher logic which matches functions against a given
 * SDK signature library.
 */
public class SdkSignatureMatcher {
	private final SdkSignatureMatcherOptions options;

	public SdkSignatureMatcher(SdkSignatureMatcherOptions opts) {
		options = opts;
	}

	/**
	 * Given an SDK signature library, attempt to match signatures against functions
	 * in the binary, using the current options for guidance.
	 * @param library The SDK signature library to match for.
	 * @param program The `Program` object representing the binary.
	 * @param addressSetView A set of addresses in the binary to search.
	 * @param monitor An asynchronous task monitor.
	 * @return a set of matches linking `Function`s to their matched signature.
	 * @throws CancelledException if the operation is cancelled by the user.
	 */
	public List<SdkSignatureMatch> match(SdkLibrary library, Program program,
			AddressSetView addressSetView, TaskMonitor monitor)
			throws CancelledException {
		List<SdkSignatureMatch> matches = new ArrayList<>();
		List<Function> candidateFunctions = getCandidateFunctions(program, addressSetView);

		// We cheat a little by creating `SdkSignatureMatch` structures for each candidate function
		// and overwriting the candidate signature data later if it gets matched.
		List<SdkSignatureMatch> candidateMatches = new ArrayList<>(candidateFunctions.size());
		for(Function f : candidateFunctions) {
			candidateMatches.add(new SdkSignatureMatch(f, SdkFunction.fromFunction(f, monitor)));
		}

		// Scan the list of candidate functions for matches.
		for(SdkFunction sdkFunc : library.getFunctions()) {
			List<SdkSignatureMatch> sigMatches = candidateMatches.stream().sequential()
					.filter(m -> isMatch(m.getMatchedSignature().getSignature(), sdkFunc.getSignature()))
					.collect(Collectors.toList());
			if(!sigMatches.isEmpty()) {
				// TODO: Log the case where one signature matches multiple functions.
				SdkSignatureMatch matched = sigMatches.get(0);
				candidateMatches.remove(matched);
				matched.setMatchedSignature(sdkFunc);
				matches.add(matched);
			}
		}

		return matches;
	}

	/**
	 * Based on the matcher options, gather all candidate functions for matching
	 * from the given address set within the program.
	 */
	@SuppressWarnings("ReassignedVariable")
	private List<Function> getCandidateFunctions(Program program, AddressSetView addressSetView) {
		// Grab all functions in the current address view.
		// Exclude functions which don't meet the minimum size requirement.
		Stream<Function> candidateFuncs = StreamSupport.stream(
				program.getFunctionManager().getFunctions(addressSetView, true).spliterator(), false
		).sequential().filter(func -> func.getBody().getNumAddresses() >= options.minimumFuncSize);


		// TODO: Fix
		// If manually-labeled functions should be excluded, remove them.
//		if(options.excludeManuallyLabelled) {
//			candidateFuncs = candidateFuncs.filter(func -> func.getSymbol().getSource() == SourceType.DEFAULT);
//		}
		return candidateFuncs.collect(Collectors.toList());
	}

	/**
	 * Determine whether the given signatures match based on the current matcher options.
	 */
	private boolean isMatch(SdkSignature lhs, SdkSignature rhs) {
		return lhs.getLength() == rhs.getLength() && lhs.getHash() == rhs.getHash();
	}
}
