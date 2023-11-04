package ghidra.ps2sdk.match;

import ghidra.ps2sdk.format.SdkFunction;
import ghidra.program.model.listing.Function;

/**
 * Dataclass mapping a program's `Function` to a matched SDK signature.
 */
public class SdkSignatureMatch {
	private final Function matchedFunction;
	private SdkFunction matchedSignature;

	public SdkSignatureMatch(Function matchedFunc, SdkFunction matchedSig) {
		matchedFunction = matchedFunc;
		matchedSignature = matchedSig;
	}

	public Function getMatchedFunction() { return matchedFunction; }
	public SdkFunction getMatchedSignature() { return matchedSignature; }

	public void setMatchedSignature(SdkFunction sig) { matchedSignature = sig; }
}
