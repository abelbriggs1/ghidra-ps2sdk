package ghidra.ps2sdk.match;

import java.util.List;

/**
 * Dataclass containing the results of matching a full SDK signature library
 * against a program.
 */
public class SdkSignatureLibraryMatches {
    private final String name;
    private final List<SdkSignatureMatch> matches;

	public SdkSignatureLibraryMatches(String libraryName, List<SdkSignatureMatch> matchedSignatures) {
		name = libraryName;
		matches = matchedSignatures;
	}

	public String getName() { return name; }
	public List<SdkSignatureMatch> getMatches() { return matches; }
}
