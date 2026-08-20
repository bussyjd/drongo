package com.sparrowwallet.drongo.btq;

import com.sparrowwallet.drongo.protocol.Script;
import com.sparrowwallet.drongo.protocol.Sha256Hash;
import com.sparrowwallet.drongo.protocol.SigHash;
import com.sparrowwallet.drongo.protocol.Transaction;
import com.sparrowwallet.drongo.protocol.TransactionOutput;
import com.sparrowwallet.drongo.protocol.TransactionWitness;
import com.sparrowwallet.drongo.psbt.PSBT;
import com.sparrowwallet.drongo.psbt.PSBTInput;
import com.sparrowwallet.drongo.psbt.PSBTProofException;

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
        return psbt.extractTransaction();
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
