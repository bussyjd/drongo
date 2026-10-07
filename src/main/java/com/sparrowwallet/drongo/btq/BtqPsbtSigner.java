package com.sparrowwallet.drongo.btq;

import com.sparrowwallet.drongo.protocol.Script;
import com.sparrowwallet.drongo.protocol.ScriptType;
import com.sparrowwallet.drongo.protocol.Sha256Hash;
import com.sparrowwallet.drongo.protocol.SigHash;
import com.sparrowwallet.drongo.protocol.Transaction;
import com.sparrowwallet.drongo.protocol.TransactionOutput;
import com.sparrowwallet.drongo.protocol.TransactionWitness;
import com.sparrowwallet.drongo.psbt.PSBT;
import com.sparrowwallet.drongo.psbt.PSBTInput;
import com.sparrowwallet.drongo.psbt.PSBTProofException;
import com.sparrowwallet.drongo.psbt.PSBTSignatureException;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Signs and finalizes Bitcoin Quantum P2MR (BIP360) inputs in a drongo {@link PSBT}.
 * <p>
 * The sighash is computed with drongo's consensus {@link Transaction#hashForTaprootSignature} - BTQ's
 * P2MR script-path sighash is BIP341 tapscript sighash with {@code SIGHASH_ALL} - so the byte-exact
 * serialization of prevouts/amounts/scripts/sequences/outputs is shared with the transaction drongo
 * broadcasts, eliminating any independent-serialization risk. Signing uses {@link Mldsa44}; the witness
 * is assembled as {@code [signature, leafScript, controlBlock]}, matching the Qparrow implementation
 * validated against BTQ Core on public testnet.
 */
public final class BtqPsbtSigner {
    private BtqPsbtSigner() {
    }

    /** The P2MR script-path (BIP341, SIGHASH_ALL) sighash for the given input; requires its leaf script and every input's witness UTXO. */
    public static byte[] sighash(PSBT psbt, int inputIndex) {
        PSBTInput input = psbt.getPsbtInputs().get(inputIndex);
        byte[] leafScript = input.getP2mrLeafScript();
        if(leafScript == null) {
            throw new IllegalStateException("input " + inputIndex + " is not a P2MR input (no leaf script)");
        }
        return sighash(psbt, inputIndex, leafScript);
    }

    /** The P2MR script-path (BIP341, SIGHASH_ALL) sighash for the given input spent through the given leaf script. */
    static byte[] sighash(PSBT psbt, int inputIndex, byte[] leafScript) {
        List<TransactionOutput> spentOutputs = new ArrayList<>(psbt.getPsbtInputs().size());
        for(int i = 0; i < psbt.getPsbtInputs().size(); i++) {
            TransactionOutput witnessUtxo = psbt.getPsbtInputs().get(i).getWitnessUtxo();
            if(witnessUtxo == null) {
                throw new IllegalStateException("input " + i + " has no witness UTXO; a P2MR sighash needs every input's spent output");
            }
            spentOutputs.add(witnessUtxo);
        }

        Sha256Hash hash = psbt.getTransaction().hashForTaprootSignature(spentOutputs, inputIndex, true, new Script(leafScript), SigHash.ALL, null);
        return hash.getBytes();
    }

    /**
     * Verify the finalized witness of a P2MR input against the transaction this PSBT represents, before its fields are copied
     * into an open transaction. Only the single-key, single-leaf tree this wallet builds can be verified; any other witness,
     * tree shape or leaf template fails closed rather than being copied unchecked.
     *
     * @throws PSBTSignatureException if the witness does not commit to the input's UTXO or its ML-DSA signature does not verify
     */
    public static void verifyFinalizedInput(PSBT psbt, int inputIndex) throws PSBTSignatureException {
        PSBTInput input = psbt.getPsbtInputs().get(inputIndex);
        TransactionOutput witnessUtxo = input.getWitnessUtxo();
        if(witnessUtxo == null) {
            throw new PSBTSignatureException("P2MR input " + inputIndex + " provides no witness UTXO to verify its signature against");
        }
        if(input.getFinalScriptSig() != null && input.getFinalScriptSig().getProgram().length > 0) {
            throw new PSBTSignatureException("P2MR input " + inputIndex + " is finalized with a non-empty scriptSig");
        }
        TransactionWitness witness = input.getFinalScriptWitness();
        if(witness == null || witness.getPushCount() != 3) {
            throw new PSBTSignatureException("P2MR input " + inputIndex + " is not finalized with a [signature, leaf script, control block] witness");
        }

        List<byte[]> pushes = witness.getPushes();
        byte[] signature = pushes.get(0);
        byte[] leafScript = pushes.get(1);
        byte[] controlBlock = pushes.get(2);

        if(!Arrays.equals(controlBlock, P2MR.singleLeafControlBlock())) {
            throw new PSBTSignatureException("P2MR input " + inputIndex + " is finalized through a multi-leaf tree, which this wallet cannot verify");
        }
        byte[] publicKey = P2MR.publicKeyFromSingleKeyLeafScript(leafScript);
        if(publicKey == null) {
            throw new PSBTSignatureException("P2MR input " + inputIndex + " is finalized with a leaf script that is not a single-key ML-DSA leaf");
        }
        if(!Arrays.equals(P2MR.outputScript(P2MR.tapLeafHash(leafScript)), witnessUtxo.getScript().getProgram())) {
            throw new PSBTSignatureException("P2MR input " + inputIndex + " is finalized with a leaf that its UTXO does not commit to");
        }
        if(signature.length != Mldsa44.TRANSACTION_SIGNATURE_BYTES) {
            throw new PSBTSignatureException("P2MR input " + inputIndex + " is finalized with a signature of " + signature.length + " bytes");
        }

        byte[] sighash;
        try {
            sighash = sighash(psbt, inputIndex, leafScript);
        } catch(IllegalStateException e) {
            throw new PSBTSignatureException("P2MR input " + inputIndex + " cannot be verified: " + e.getMessage());
        }
        if(!Mldsa44.verifyTransactionHash(publicKey, sighash, signature)) {
            throw new PSBTSignatureException("P2MR input " + inputIndex + " is finalized with an ML-DSA signature that does not verify");
        }
    }

    /**
     * Verify the BIP360 Dilithium script signature (field 0x1b) an input carries, if any, as a PSBT is parsed or combined. The
     * signature must be keyed to the input's own leaf script, that leaf must be committed to by the input's P2MR UTXO through its
     * control block, the leaf must push the signing public key, and the ML-DSA-44 signature must verify over the SIGHASH_ALL
     * P2MR sighash. Anything that cannot be checked fails closed, as an unverifiable ECDSA or Schnorr signature does.
     *
     * @throws PSBTSignatureException if the input's Dilithium signature is unverifiable or does not verify
     */
    public static void verifyDilithiumSignature(PSBT psbt, int inputIndex) throws PSBTSignatureException {
        PSBTInput input = psbt.getPsbtInputs().get(inputIndex);
        byte[] signature = input.getP2mrDilithiumSignature();
        if(signature == null) {
            return;
        }

        TransactionOutput witnessUtxo = input.getWitnessUtxo();
        if(witnessUtxo == null || !ScriptType.P2MR.isScriptType(witnessUtxo.getScript())) {
            throw new PSBTSignatureException("Input " + inputIndex + " provides a Dilithium signature but no P2MR witness UTXO to verify it against");
        }
        byte[] leafScript = input.getP2mrLeafScript();
        if(leafScript == null) {
            throw new PSBTSignatureException("P2MR input " + inputIndex + " provides a Dilithium signature without the leaf script it signs");
        }
        if(!Arrays.equals(P2MR.tapLeafHash(leafScript), input.getP2mrDilithiumLeafHash())) {
            throw new PSBTSignatureException("P2MR input " + inputIndex + " provides a Dilithium signature for a leaf other than its leaf script");
        }
        byte[] merkleRoot = P2MR.merkleRootFromControlBlock(leafScript, input.getP2mrControlBlock());
        if(merkleRoot == null || !Arrays.equals(P2MR.outputScript(merkleRoot), witnessUtxo.getScript().getProgram())) {
            throw new PSBTSignatureException("P2MR input " + inputIndex + " provides a Dilithium signature for a leaf its UTXO does not commit to");
        }
        byte[] publicKey = input.getP2mrDilithiumPubKey();
        if(!containsPublicKeyPush(leafScript, publicKey)) {
            throw new PSBTSignatureException("P2MR input " + inputIndex + " provides a Dilithium signature from a key its leaf script does not contain");
        }

        byte[] sighash;
        try {
            sighash = sighash(psbt, inputIndex, leafScript);
        } catch(IllegalStateException e) {
            throw new PSBTSignatureException("Unverifiable Dilithium signature provided for P2MR input " + inputIndex + ": " + e.getMessage());
        }
        if(!Mldsa44.verifyTransactionHash(publicKey, sighash, signature)) {
            throw new PSBTSignatureException("Dilithium signature does not verify against the provided public key for P2MR input " + inputIndex);
        }
    }

    /** Whether the leaf script pushes the given ML-DSA public key with the {@code OP_PUSHDATA2 <1312>} encoding a Dilithium leaf uses. */
    private static boolean containsPublicKeyPush(byte[] leafScript, byte[] publicKey) {
        if(publicKey == null || publicKey.length != Mldsa44.PUBLIC_KEY_BYTES) {
            return false;
        }
        byte[] push = Arrays.copyOf(P2MR.singleKeyLeafScript(publicKey), 3 + publicKey.length);
        for(int offset = 0; offset + push.length <= leafScript.length; offset++) {
            if(Arrays.equals(leafScript, offset, offset + push.length, push, 0, push.length)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Sign the P2MR inputs whose index maps to a 32-byte ML-DSA seed, storing the BIP360 0x1b field on each.
     * The seed's derived public key must match the input's committed leaf script. Returns the signed sighashes.
     */
    public static List<byte[]> sign(PSBT psbt, Map<Integer, byte[]> inputSeeds) {
        List<byte[]> sighashes = new ArrayList<>(inputSeeds.size());
        for(Map.Entry<Integer, byte[]> entry : inputSeeds.entrySet()) {
            int inputIndex = entry.getKey();
            byte[] seed = entry.getValue();
            PSBTInput input = psbt.getPsbtInputs().get(inputIndex);

            byte[] publicKey = Mldsa44.publicKeyFromSeed(seed);
            byte[] expectedLeaf = P2MR.singleKeyLeafScript(publicKey);
            if(!Arrays.equals(expectedLeaf, input.getP2mrLeafScript())) {
                throw new IllegalStateException("input " + inputIndex + " leaf script does not commit to the signing key");
            }

            byte[] sighash = sighash(psbt, inputIndex);
            byte[] signature = Mldsa44.signTransactionHash(seed, sighash);
            if(!Mldsa44.verifyTransactionHash(publicKey, sighash, signature)) {
                throw new IllegalStateException("ML-DSA signature for input " + inputIndex + " failed to verify");
            }

            byte[] leafHash = P2MR.tapLeafHash(input.getP2mrLeafScript());
            input.setP2mrDilithiumSignature(publicKey, leafHash, signature);
            sighashes.add(sighash);
        }
        return sighashes;
    }

    /**
     * Assemble the P2MR witness {@code [signature, leafScript, controlBlock]} for every signed input and
     * return the finalized network transaction. Inputs without a Dilithium signature are left untouched.
     */
    public static Transaction finalise(PSBT psbt) throws PSBTProofException {
        finaliseInputs(psbt);
        return psbt.extractTransaction();
    }

    /** Assemble the P2MR witness {@code [signature, leafScript, controlBlock]} for every signed input, without extracting. */
    public static void finaliseInputs(PSBT psbt) {
        Transaction transaction = psbt.getTransaction();
        for(int i = 0; i < psbt.getPsbtInputs().size(); i++) {
            PSBTInput input = psbt.getPsbtInputs().get(i);
            byte[] signature = input.getP2mrDilithiumSignature();
            if(signature == null) {
                continue;
            }
            byte[] leafScript = Objects.requireNonNull(input.getP2mrLeafScript(), "signed P2MR input is missing its leaf script");
            byte[] controlBlock = Objects.requireNonNull(input.getP2mrControlBlock(), "signed P2MR input is missing its control block");
            TransactionWitness witness = new TransactionWitness(transaction, List.of(signature, leafScript, controlBlock));
            input.setFinalScriptWitness(witness);
        }
    }

    /** The transaction fee in satoshis: sum of spent (witness UTXO) amounts minus sum of output amounts. */
    public static long feeSats(PSBT psbt) {
        long inputs = 0;
        for(PSBTInput input : psbt.getPsbtInputs()) {
            TransactionOutput witnessUtxo = input.getWitnessUtxo();
            if(witnessUtxo == null) {
                throw new IllegalStateException("cannot compute fee: an input has no witness UTXO");
            }
            inputs += witnessUtxo.getValue();
        }
        long outputs = 0;
        for(TransactionOutput output : psbt.getTransaction().getOutputs()) {
            outputs += output.getValue();
        }
        return inputs - outputs;
    }
}
