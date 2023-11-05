package ghidra.ps2sdk;

import com.google.common.io.Files;
import generic.jar.ResourceFile;
import generic.jar.ResourceFileFilter;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.plugin.core.datamgr.archive.DuplicateIdException;
import ghidra.app.services.DataTypeManagerService;
import ghidra.framework.Application;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Program;
import ghidra.ps2sdk.format.SdkLibrary;
import ghidra.ps2sdk.format.SdkLibraryParser;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * Dataclass which contains all components necessary to analyze a binary
 * for a given PS2 SDK version.
 */
public class Ps2SdkData {
    private static final String SDK_DIR_FMT = "sdk/%s/";
	private static final String SDK_LIB_DIR_FMT = SDK_DIR_FMT + "libs/";
    private static final String DATABASE_FMT = "sdk_%s";

    /**
     * Binary signature data for symbols exported by this SDK version, parsed from file.
     */
    private final List<SdkLibrary> sdkLibraries;

    /**
     * The loaded type/function definition database for this SDK version.
     */
    private final DataTypeManager sdkTypeDatabase;

    private Ps2SdkData(List<SdkLibrary> sdkLibs, DataTypeManager sdkDb) {
		sdkLibraries = sdkLibs;
        sdkTypeDatabase = sdkDb;
    }

    /**
     * Retrieve the SDK binary signatures.
     */
    public List<SdkLibrary> getSdkLibraries() {
        return sdkLibraries;
    }

    /**
     * Retrieve the type database for this SDK version.
     */
    public DataTypeManager getTypeDatabase() {
        return sdkTypeDatabase;
    }

	/**
	 * Given a PS2 SDK version, load the data necessary to analyze the binary.
	 * @param program the program to analyze.
	 * @param version the SDK version to load.
	 * @return a data object containing the loaded data.
	 */
	public static Ps2SdkData fromSdkVersion(Program program, Ps2SdkVersion version)
			throws DuplicateIdException, IOException {
		DataTypeManager sdkDb = loadTypeDatabase(program, version);
		List<SdkLibrary> sdkLibs = loadSdkLibraries(version);
		return new Ps2SdkData(sdkLibs, sdkDb);
	}

	private static ResourceFile getLibrariesDir(Ps2SdkVersion version) throws IOException {
		final String directory = String.format(SDK_LIB_DIR_FMT, version.getBinaryVersion());
		return Application.getModuleDataSubDirectory(directory);
	}

    private static DataTypeManager loadTypeDatabase(Program program, Ps2SdkVersion version)
        throws DuplicateIdException, IOException {

        // Try to find an open database first.
        final String dbName = String.format(DATABASE_FMT, version.getBinaryVersion());
        DataTypeManagerService service = AutoAnalysisManager.getAnalysisManager(program).getDataTypeManagerService();
        var managers = service.getDataTypeManagers();
        for (var m : managers) {
            if (m.getName().equals(dbName)) {
                return m;
            }
        }
        // Try to load the database from file.
        return service.openDataTypeArchive(dbName);
    }

	private static List<SdkLibrary> loadSdkLibraries(Ps2SdkVersion version) throws IOException {
		ResourceFile libDir = getLibrariesDir(version);
		ResourceFile[] libFiles = libDir.listFiles(new SdkLibrariesFilter());

		List<SdkLibrary> libs = new ArrayList<>(libFiles.length);
		for(ResourceFile f : libFiles) {
			libs.add(SdkLibraryParser.deserialize(f.getFile(false)));
		}
		return libs;
	}

	/**
	 * Private filter class for loading SDK library files.
	 */
	private static class SdkLibrariesFilter implements ResourceFileFilter {
		public boolean accept(ResourceFile file) {
			return Files.getFileExtension(file.getName()).equals("json");
		}
	}
}
