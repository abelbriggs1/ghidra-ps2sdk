package ghidra.ps2sdk.format;

import com.google.gson.annotations.SerializedName;
import ghidra.program.model.listing.Function;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Dataclass for an SDK function symbol and its binary signatures, which can
 * be used to find this symbol in different executables.
 */
public final class SdkFunction {
	/**
	 * The label used for this SDK symbol. Required.
	 */
	@SerializedName("label")
	private final String label;

	/**
	 * The signature data for this SDK symbol. Required.
	 */
	@SerializedName("signature")
	private final SdkSignature signature;

	public SdkFunction(String name, SdkSignature sig) {
		label = name;
		signature = sig;
	}

	public String getLabel() {
		return label;
	}

	public SdkSignature getSignature() {
		return signature;
	}

	/**
	 * Construct an SDK function signature from the given function.
	 * @param func The function to create a signature for.
	 * @param monitor A task monitor, used to cancel this operation from another thread if
	 *                the user desires.
	 * @return The created signature.
	 * @throws CancelledException if the user cancels via the UI.
	 */
	public static SdkFunction fromFunction(Function func, TaskMonitor monitor) throws CancelledException {
		return new SdkFunction(func.getName(), SdkSignature.fromFunction(func, monitor));
	}
}
