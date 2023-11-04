package ghidra.ps2sdk.format;

import com.google.gson.annotations.SerializedName;
import ghidra.program.model.listing.Function;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.ps2sdk.match.SdkSignatureHasher;

/**
 * Dataclass for an SDK "signature", which represents a set of hashes generated from a symbol.
 * These hashes can be matched against functions in any binary to look for common symbols.
 */
public final class SdkSignature {

	/**
	 * Length of the function in bytes. Required.
	 */
	@SerializedName("length")
	private final Integer length;

	/**
	 * A `FNV1a64` hash value which represents the hash of the following:
	 * - all bits representing instruction opcodes
	 * - all bits representing register operands
	 * - all bits representing scalar immediate operands for most trivial operations
	 * Required.
	 */
	@SerializedName("hash")
	private final Long hash;

	public SdkSignature(Integer lenBytes, Long hashValue) {
		length = lenBytes;
		hash = hashValue;
	}

	public int getLength() {
		return length;
	}

	public long getHash() {
		return hash;
	}

	/**
	 * Construct a new signature from the given function.
	 * @param func The function to create a signature for.
	 * @param monitor A task monitor, used to cancel this operation from another thread if
	 *                the user desires.
	 * @return The created signature.
	 * @throws CancelledException if the user cancels via the UI.
	 */
	public static SdkSignature fromFunction(Function func, TaskMonitor monitor) throws CancelledException {
		return new SdkSignature(
				(int) func.getBody().getNumAddresses(),
				SdkSignatureHasher.INSTANCE.hash(func, monitor)
		);
	}
}

