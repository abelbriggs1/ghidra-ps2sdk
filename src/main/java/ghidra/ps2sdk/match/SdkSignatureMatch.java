package ghidra.ps2sdk.match;

import ghidra.ps2sdk.format.SdkFunction;
import ghidra.program.model.listing.Function;

import java.util.List;

/**
 * Dataclass mapping a program's `Functions` to a matched SDK signature.
 * Multiple functions may match a single signature. It is the user's responsibility to
 * determine how to resolve this case.
 */
public class SdkSignatureMatch {
	private final List<Function> matchedFunctions;
	private SdkFunction matchedSignature;

	public SdkSignatureMatch(List<Function> matchedFuncs, SdkFunction matchedSig) {
		matchedFunctions = matchedFuncs;
		matchedSignature = matchedSig;
	}

	public List<Function> getMatchedFunctions() { return matchedFunctions; }
	public SdkFunction getMatchedSignature() { return matchedSignature; }

	public void setMatchedSignature(SdkFunction sig) { matchedSignature = sig; }
}
