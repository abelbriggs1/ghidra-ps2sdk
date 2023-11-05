package ghidra.ps2sdk.match;

import ghidra.ps2sdk.format.SdkFunction;
import ghidra.ps2sdk.format.SdkLibrary;
import ghidra.ps2sdk.format.SdkSignature;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
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
	 * Given a set of SDK signature libraries, match each library's signatures against
	 * functions in the binary, using the current options for guidance.
	 * The user is responsible for applying the matches and resolving any conflicts or
	 * signatures with multiple matches.
	 * @param libraries The SDK signature libraries to match for.
	 * @param program The `Program` object representing the binary.
	 * @param addressSetView A set of addresses in the binary to search.
	 * @param monitor An asynchronous task monitor.
	 * @return a set of matches for each given library linking `Function`s to their matched signature.
	 * @throws CancelledException if the operation is cancelled by the user.
	 */
	public List<SdkSignatureLibraryMatches> match(List<SdkLibrary> libraries, Program program,
			AddressSetView addressSetView, TaskMonitor monitor)
			throws CancelledException {
		List<SdkSignatureLibraryMatches> matchLibs = new ArrayList<>(libraries.size());
		for(SdkLibrary lib : libraries) {
			matchLibs.add(match(lib, program, addressSetView, monitor));
		}
		return matchLibs;
	}
	

	/**
	 * Given an SDK signature library, attempt to match signatures against functions
	 * in the binary, using the current options for guidance.
	 * The user is responsible for applying the matches and resolving any conflicts
	 * or signatures with multiple matches.
	 * @param library The SDK signature library to match for.
	 * @param program The `Program` object representing the binary.
	 * @param addressSetView A set of addresses in the binary to search.
	 * @param monitor An asynchronous task monitor.
	 * @return a set of matches linking `Function`s to their matched signature.
	 * @throws CancelledException if the operation is cancelled by the user.
	 */
	public SdkSignatureLibraryMatches match(SdkLibrary library, Program program,
			AddressSetView addressSetView, TaskMonitor monitor)
			throws CancelledException {
		List<SdkSignatureMatch> matches = new ArrayList<>();
		List<Function> candidateFunctions = getCandidateFunctions(program, addressSetView);

		// Create signatures for all candidate functions.
		List<SdkSignaturePair> candidateMatches = new ArrayList<>(candidateFunctions.size());
		for(Function f : candidateFunctions) {
			candidateMatches.add(new SdkSignaturePair(f, SdkSignature.fromFunction(f, monitor)));
		}

		// Scan the list of candidate functions for matches.
		for(SdkFunction sdkFunc : library.getFunctions()) {
			List<SdkSignaturePair> sigMatches = candidateMatches.stream().sequential()
					.filter(m -> isMatch(m.sig, sdkFunc.getSignature()))
					.toList();
			if(!sigMatches.isEmpty()) {
				List<Function> matchedFuncs = sigMatches.stream().map(m -> m.func).toList();
				SdkSignatureMatch matched = new SdkSignatureMatch(matchedFuncs, sdkFunc);
				matches.add(matched);
			}
		}

		
		return new SdkSignatureLibraryMatches(library.getName(), matches);
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

		return candidateFuncs.collect(Collectors.toList());
	}

	/**
	 * Determine whether the given signatures match based on the current matcher options.
	 */
	private boolean isMatch(SdkSignature lhs, SdkSignature rhs) {
		return lhs.getLength() == rhs.getLength() && lhs.getHash() == rhs.getHash();
	}

	/**
	 * Inner class used to easily map a function to its signature.
	 */
	private static class SdkSignaturePair {
		public final Function func;
		public final SdkSignature sig;

		public SdkSignaturePair(Function function, SdkSignature signature) {
			func = function;
			sig = signature;
		}
	}
}
