package ghidra.ps2sdk;

/**
 * Enumeration for supported PS2 SDK versions.
 */
public enum Ps2SdkVersion {
    V2_0_0("v2.0", "2000");

    /**
     * The 'full' version string for this SDK version, as would be displayed to users.
     */
    private final String fullVersion;

    /**
     * The version string as formatted for an SDK binary symbol.
     */
    private final String binaryVersion;

    Ps2SdkVersion(String fullVer, String binaryVer) {
        fullVersion = fullVer;
        binaryVersion = binaryVer;
    }

    public String getFullVersion() {
        return fullVersion;
    }

    public String getBinaryVersion() {
        return binaryVersion;
    }
}
