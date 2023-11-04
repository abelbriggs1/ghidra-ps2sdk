package ghidra.ps2sdk.match;

import generic.hash.FNV1a64MessageDigest;
import generic.hash.MessageDigest;
import ghidra.app.plugin.match.AbstractFunctionHasher;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;

/**
 * Hasher which processes the following for a function:
 * - instruction opcode bits
 * - register operand bits
 * - scalar immediate operands for instructions which are not used to calculate
 *   addresses or load/store memory
 */
public class SdkSignatureHasher extends AbstractFunctionHasher {
	private static final String[] SCALAR_INSTR_MNEMS = { "li", "andi", "dsll", "dsll32", "dsra",
			"dsra32", "dsrl", "dsrl32", "ori", "sll", "slti", "sltiu", "sra", "srl", "xori"};
	private static final HashSet<String> ACCEPTED_SCALAR_OP_MNEMONICS = new HashSet<>(Arrays.asList(SCALAR_INSTR_MNEMS));
	public static final SdkSignatureHasher INSTANCE = new SdkSignatureHasher();

	protected MessageDigest digest;

	protected SdkSignatureHasher() {
		digest = new FNV1a64MessageDigest();
	}

	@Override
	public int commonBitCount(Function funcA, Function funcB, TaskMonitor monitor) {
		// Unimplemented.
		return 0;
	}

	/**
	 * Given some code units and their total size in bytes, calculate the FNV1a64 hash.
	 */
	@Override
	protected long hash(TaskMonitor monitor, ArrayList<CodeUnit> units, int byteCount)
			throws CancelledException {
		byte[] buffer = new byte[byteCount];
		int offset = 0;

		// Create a buffer consisting of each instruction's bytes with everything
		// except the instruction and register operand bits masked off.
		for (CodeUnit codeUnit : units) {
			monitor.checkCancelled();
			try {
				codeUnit.getBytesInCodeUnit(buffer, offset);
				applyMask(buffer, offset, codeUnit);
			} catch (MemoryAccessException e) {
				Msg.warn(this, "Could not get code unit bytes at " + codeUnit.getAddress());
			}
			offset += codeUnit.getLength();
		}
		if (offset != byteCount) {
			throw new IllegalStateException("did NOT use all the codeUnit buffer bytes");
		}

		// Hash the buffer.
		synchronized (digest) {
			digest.reset();
			digest.update(buffer, monitor);
			return digest.digestLong();
		}
	}

	/**
	 * Given an instruction, copy its byte representation to the buffer at the given
	 * offset while masking off everything except the opcode, register operand, and scalar immediate operand
	 * bits.
	 */
	private static void applyMask(byte[] buffer, int offset, CodeUnit codeUnit) {
		if (!(codeUnit instanceof Instruction instr)) {
			return;
		}

		InstructionPrototype instrProto = instr.getPrototype();
		List<Mask> masks = new ArrayList<>();

		// Start with the instruction mask.
		masks.add(instrProto.getInstructionMask());

		// If any operands are registers or scalar immediates (on certain instructions),
		// OR their mask with the instruction mask.
		for (int i = 0; i < instr.getNumOperands(); i++) {
			int type = instr.getOperandType(i);
			Mask opMask = instrProto.getOperandValueMask(i);

			if (OperandType.isRegister(type)) {
				masks.add(opMask);
			} else if (OperandType.isScalar(type) && ACCEPTED_SCALAR_OP_MNEMONICS.contains(instr.getMnemonicString())) {
				masks.add(opMask);
			}
		}

		// OR all of the masks together.
		Mask finalMask = orMasks(masks);
		if (finalMask == null) {
			return;
		}

		// Apply the mask to the buffer.
		try {
			finalMask.applyMask(buffer, offset, buffer, offset);
		} catch (IncompatibleMaskException e) {
			// Shouldn't happen.
			throw new RuntimeException(e);
		}
	}

	/**
	 * Perform an OR operation on the given `Mask`s. Returns null if no masks are given or
	 * the lengths of the masks do not match.
	 */
	private static Mask orMasks(List<Mask> masks) {
		if (masks.isEmpty()) {
			return null;
		}

		int expectedLength = masks.get(0).getBytes().length;
		boolean lengthsMatch = masks.stream().allMatch(m -> m.getBytes().length == expectedLength);
		if (!lengthsMatch) {
			return null;
		}

		// OR every mask together.
		byte[] intermedMask = new byte[expectedLength];
		for (Mask mask : masks) {
			byte[] byteMask = mask.getBytes();
			for (int i = 0; i < expectedLength; i++) {
				intermedMask[i] |= byteMask[i];
			}
		}
		return new MaskImpl(intermedMask);
	}
}
