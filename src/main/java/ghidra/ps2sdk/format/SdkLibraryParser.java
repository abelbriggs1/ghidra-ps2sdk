package ghidra.ps2sdk.format;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonParseException;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;

import java.io.*;
import java.nio.file.Files;

/**
 * Parser and validator functions for an "SDK signatures library" JSON file.
 */
public final class SdkLibraryParser {
	private static final String MISSING_FMT = "Missing required field: %s";

	private SdkLibraryParser() {
		// not instantiable
	}

	/**
	 * Throw a JsonParseException with a descriptive message if the given
	 * object is `null`.
	 */
	private static void required(Object field, String fieldName) throws JsonParseException {
		if (field == null) {
			throw new JsonParseException(String.format(MISSING_FMT, fieldName));
		}
	}

	/**
	 * Verify required fields are populated in a serialized/deserialized SDK library.
	 * Throws a JsonParseException if a field is missing.
	 * <p>
	 * gson parses assuming that all attributes are optional. Whatever it doesn't parse, it
	 * sets to `null`, and assumes the user is responsible for validation.
	 * <p>
	 * This would be fine if Gson had support for easily specifying that an attribute is `@Required`
	 * in some way... but it doesn't, and the maintainers explicitly have no interest in supporting it.
	 * Additionally, methods of extending Gson to support required attributes are so verbose and
	 * fragile that you might as well perform manual deserialization,
	 * which defeats the point of Gson in the first place!
	 * <p>
	 * If the format is extended in the future, it would be good to find some acceptable way to
	 * implement `@Required` so none of this manual checking is needed.
	 */
	private static void verifyRequired(SdkLibrary library) throws JsonParseException {
		required(library.getName(), "name");
		required(library.getFunctions(), "functions");
		for (SdkFunction f : library.getFunctions()) {
			required(f.getLabel(), "label");
			SdkSignature sig = f.getSignature();
			required(sig, "signature");
			{
				required(sig.getLength(), "length");
				required(sig.getHash(), "hash");
			}
		}
	}

	/**
	 * Deserialize an SDK signature library from a JSON file and validate the data.
	 *
	 * @param jsonFile The JSON file to deserialize.
	 * @return The deserialized SDK library.
	 * @throws IOException
	 * @throws JsonParseException
	 */
	public static SdkLibrary deserialize(File jsonFile) throws IOException, JsonParseException {
		byte[] json = Files.readAllBytes(jsonFile.toPath());
		JsonReader reader = new JsonReader(new InputStreamReader(new ByteArrayInputStream(json)));
		GsonBuilder gsonBuilder = new GsonBuilder();
		Gson gson = gsonBuilder.create();

		SdkLibrary result = gson.fromJson(reader, SdkLibrary.class);
		verifyRequired(result);
		return result;
	}

	/**
	 * Validate an SDK signature library and serialize it to JSON file.
	 *
	 * @param jsonFile The JSON file to write to.
	 * @param library  The library to serialize.
	 * @throws IOException
	 * @throws JsonParseException
	 */
	public static void serialize(File jsonFile, SdkLibrary library) throws IOException, JsonParseException {
		verifyRequired(library);

		try (JsonWriter writer = new JsonWriter(new OutputStreamWriter(new FileOutputStream(jsonFile)))) {
			// Set a small indent. This does significantly increase the size of the file,
			// but they generally won't be that big to begin with, and it's useful to
			// make these files somewhat human-readable for debugging purposes.
			writer.setIndent("  ");
			GsonBuilder builder = new GsonBuilder();
			Gson gson = builder.create();
			gson.toJson(library, SdkLibrary.class, writer);
		}
	}
}
