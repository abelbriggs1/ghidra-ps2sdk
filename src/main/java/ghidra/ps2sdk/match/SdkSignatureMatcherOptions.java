package ghidra.ps2sdk.match;

/**
 * Dataclass which contains all options for the common SDK signature matcher.
 */
public class SdkSignatureMatcherOptions {

	public static final String OPTION_MINIMUM_FUNC_SIZE_NAME = "Minimum Function Size";
	public static final String OPTION_MINIMUM_FUNC_SIZE_DESC =
			"Minimum function size, in bytes, for the matcher to analyze. " +
			"16 is the default, and the recommended minimum - any lower and a significant " +
			"number of mismatches are likely to appear.";
	public int minimumFuncSize = 16;
}
