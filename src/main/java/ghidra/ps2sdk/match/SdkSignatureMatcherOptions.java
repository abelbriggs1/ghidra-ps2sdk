package ghidra.ps2sdk.match;

/**
 * Dataclass which contains all options for the common SDK signature matcher.
 */
public class SdkSignatureMatcherOptions {

	public static final String OPTION_EXCLUDE_LABELLED_NAME = "Exclude Labelled Functions";
	public static final String OPTION_EXCLUDE_LABELLED_DESC =
			"Exclude all functions which already have labels applied from sources " +
			"other than auto-analysis. This should almost always be enabled - if disabled, " +
			"manually-labeled/decompiled functions may be overwritten if matched. " +
			"However, in binaries with STABS symbols, this option should be disabled " +
			"for initial analysis.";
	public boolean excludeManuallyLabelled = true;

	public static final String OPTION_MINIMUM_FUNC_SIZE_NAME = "Minimum Function Size";
	public static final String OPTION_MINIMUM_FUNC_SIZE_DESC =
			"Minimum function size, in bytes, for the matcher to analyze. " +
			"Functions in the SDK are almost always 16 bytes or longer. Reducing this " +
			"below 16 may lead to false positives.";
	public int minimumFuncSize = 16;
}
