/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.ps2sdk;

import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.cmd.function.CreateFunctionDefinitionCmd;
import ghidra.app.plugin.core.datamgr.archive.DuplicateIdException;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionSignature;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.ps2sdk.match.SdkSignatureLibraryMatches;
import ghidra.ps2sdk.match.SdkSignatureMatch;
import ghidra.ps2sdk.match.SdkSignatureMatcher;
import ghidra.ps2sdk.match.SdkSignatureMatcherOptions;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * Primary analyzer for this extension. Uses a hash algorithm to match functions in the
 * program against binary signatures of Playstation 2 Software Development Kit (SDK)
 * library functions.
 */
public class Ps2SdkAnalyzer extends AbstractAnalyzer {

	private static final String PS2SDK_ANALYZER_NAME = "PS2 SDK Analyzer";
	private static final String PS2SDK_ANALYZER_DESC =
			"Examines the binary to define, label, and apply known API signatures to PS2 SDK " +
			"functions.";

	private final Ps2SdkVersion version = Ps2SdkVersion.V2_0_0;

	public Ps2SdkAnalyzer() {
		super(PS2SDK_ANALYZER_NAME, PS2SDK_ANALYZER_DESC, AnalyzerType.FUNCTION_ANALYZER);
		setPriority(AnalysisPriority.FUNCTION_ANALYSIS.after());
	}

	@Override
	public boolean getDefaultEnablement(Program program) {
		return false;
	}

	@Override
	public boolean canAnalyze(Program program) {
        Language language = program.getLanguage();
        String id = language.getLanguageID().getIdAsString().toLowerCase();
        return id.startsWith("mips") || id.startsWith("r5900");
	}

	@Override
	public void registerOptions(Options options, Program program) {
		// TODO: Planned options:
		// - Choose SDK version, or auto-detect
		// - Choose how multi-matches are resolved (ignore, log, match_first)
		// - Choose the minimum length of functions to search/match
	}

	@Override
	public void optionsChanged(Options options, Program program) {
		// TODO: Update new options here
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		//
		// Load SDK data for the selected SDK version.
		//
		Ps2SdkData sdkData;
		try {
			sdkData = Ps2SdkData.fromSdkVersion(program, version);
		} catch(IOException | DuplicateIdException e) {
			log.appendMsg(PS2SDK_ANALYZER_NAME, "Failed to load SDK database - cannot analyze!");
			log.appendException(e);
			return false;
		}

		//
		// Match functions in the current address view/selection.
		//
		SdkSignatureMatcherOptions opts = new SdkSignatureMatcherOptions();
		SdkSignatureMatcher matcher = new SdkSignatureMatcher(opts);
		List<SdkSignatureLibraryMatches> libraryMatches = matcher.match(sdkData.getSdkLibraries(), program, set, monitor);

		//
		// Apply signatures.
		//
		List<Function> alreadyMatched = new ArrayList<>();
		for(SdkSignatureLibraryMatches lib : libraryMatches) {
			CategoryPath functionsCategory = new CategoryPath(CategoryPath.ROOT, lib.getName(), "functions");

			for(SdkSignatureMatch match : lib.getMatches()) {
				List<Function> matchedFuncs = match.getMatchedFunctions();
				String label = match.getMatchedSignature().getLabel();
				// TODO: Resolve conflicts - we just ignore & log matches with multiple for now.
				if(matchedFuncs.size() > 1) {
					log.appendMsg(String.format("Multiple matches for %s:", label));
					for(Function f : matchedFuncs) {
						log.appendMsg(String.format("  Matched %s ==> %s", f.getName(), label));
					}
				} else {
					Function matchFunc = matchedFuncs.get(0);
					// Only match the first encountered signature - don't overwrite.
					if(alreadyMatched.contains(matchFunc)) continue;
					alreadyMatched.add(matchFunc);
					
					DataType type = sdkData.getTypeDatabase().getDataType(functionsCategory, label);
					if(type instanceof FunctionSignature) {
						FunctionSignature funcDef = (FunctionSignature) type;
						ApplyFunctionSignatureCmd cmd = new ApplyFunctionSignatureCmd(matchFunc.getEntryPoint(), funcDef, SourceType.ANALYSIS);
						cmd.applyTo(program, monitor);
					} else {
						final String issue = type == null ? "unknown" : "invalid";
						log.appendMsg(PS2SDK_ANALYZER_NAME, String.format("%s's function signature is %s.", label, issue));
						try {
							matchFunc.setName(label, SourceType.ANALYSIS);
						} catch (DuplicateNameException | InvalidInputException e) {
							log.appendMsg(PS2SDK_ANALYZER_NAME, "SDK database label is invalid!? This is likely a bug.");
							log.appendException(e);
							return false;
						}
					}
				}
			}
		}

		return true;
	}
}
