package ghidra.ps2sdk.format;

import com.google.gson.annotations.SerializedName;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

/**
 * Dataclass representing an SDK library's name and an associated list
 * of symbols/binary signatures which this library implements.
 */
public final class SdkLibrary {

	/**
	 * The name of the library, as specified by the SDK.
	 */
	@SerializedName("name")
	private final String name;

	/**
	 * The list of symbols associated with this library.
	 */
	@SerializedName("functions")
	private final List<SdkFunction> functions;

	public SdkLibrary(String libName, List<SdkFunction> funcs) {
		name = libName;
		functions = funcs;
	}

	public String getName() {
		return name;
	}

	public List<SdkFunction> getFunctions() {
		return functions;
	}

	/**
	 * Construct an SDK signature library given a list of functions.
	 * @param name The name of the new SDK library.
	 * @param funcs The functions to construct signatures for.
	 * @param monitor A task monitor, used to cancel this operation asynchronously if the user desires.
	 * @return The constructed SDK signature library.
	 * @throws CancelledException if the user cancels via the UI.
	 */
	public static SdkLibrary fromFunctions(String name, List<Function> funcs, TaskMonitor monitor)
			throws CancelledException {
		// Lambdas can't handle `CancellationException` so this needs to be done manually.
		List<SdkFunction> sdkFuncs = new ArrayList<>(funcs.size());
		for (Function f : funcs) {
			sdkFuncs.add(SdkFunction.fromFunction(f, monitor));
		}
		return new SdkLibrary(name, sdkFuncs);
	}

	/**
	 * Construct an SDK signature library given an iterator over functions.
	 * @param name The name of the new SDK library.
	 * @param funcs The functions to construct signatures for.
	 * @param monitor A task monitor, used to cancel this operation asynchronously if the user desires.
	 * @return The constructed SDK signature library.
	 * @throws CancelledException if the user cancels via the UI.
	 */
	public static SdkLibrary fromFunctions(String name, FunctionIterator funcs, TaskMonitor monitor)
			throws CancelledException {
		return fromFunctions(
				name,
				StreamSupport.stream(funcs.spliterator(), false).collect(Collectors.toList()),
				monitor
		);
	}
}
