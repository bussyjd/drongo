package com.sparrowwallet.drongo.btq;

import com.sparrowwallet.drongo.protocol.Script;
import com.sparrowwallet.drongo.protocol.Sha256Hash;
import com.sparrowwallet.drongo.protocol.Transaction;
import com.sparrowwallet.drongo.protocol.TransactionOutput;
import com.sparrowwallet.drongo.protocol.TransactionWitness;
import com.sparrowwallet.drongo.psbt.PSBT;
import com.sparrowwallet.drongo.psbt.PSBTInput;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

/**
 * Tests the P2MR signing service. The golden sighash is produced by an independent Python BIP341
 * tapscript-sighash reference for a fixed transaction, proving drongo's consensus
 * {@link Transaction#hashForTaprootSignature} matches BTQ's proven P2MR sighash byte-for-byte.
 */
public class BtqPsbtSignerTest {
    private static final HexFormat HEX = HexFormat.of();
    //Golden sighash for the fixed tx below (independent Python BIP341 reference, SIGHASH_ALL, script path)
    private static final String GOLDEN_SIGHASH = "daf93b222687c1788c26ac6a153420849ee16460e80aba7272711d39d7874d48";

    private static byte[] patternPublicKey() {
        byte[] pubKey = new byte[Mldsa44.PUBLIC_KEY_BYTES];
        for(int i = 0; i < pubKey.length; i++) {
            pubKey[i] = (byte)(i & 0xff);
        }
        return pubKey;
    }

    /** Build the exact fixed transaction the Python golden vector was computed over. */
    private static PSBT buildFixedPsbt(byte[] pubKey) {
        byte[] merkleRoot = P2MR.merkleRootForPublicKey(pubKey);
        byte[] leafScript = P2MR.singleKeyLeafScript(pubKey);
        Script outputScript = new Script(P2MR.outputScript(merkleRoot));

        byte[] prevHash = new byte[32];
        Arrays.fill(prevHash, (byte)0x11);

        Transaction tx = new Transaction();
        tx.setVersion(2);
        tx.addInput(Sha256Hash.wrap(prevHash), 0, new Script(new byte[0])); //default sequence 0xffffffff
        tx.addOutput(90_000L, outputScript);

        PSBT psbt = new PSBT(tx);
        PSBTInput input = psbt.getPsbtInputs().get(0);
        input.setWitnessUtxo(new TransactionOutput(tx, 100_000L, outputScript));
        input.setP2mrLeaf(leafScript, (byte)P2MR.LEAF_VERSION, P2MR.singleLeafControlBlock());
        input.setP2mrMerkleRoot(merkleRoot);
        return psbt;
    }

    @Test
    public void testLeafScriptRoundTripsThroughScript() {
        //The 1312-byte OP_PUSHDATA2 leaf must round-trip through drongo's Script parser
        byte[] leaf = P2MR.singleKeyLeafScript(patternPublicKey());
        Assertions.assertArrayEquals(leaf, new Script(leaf).getProgram());
    }

    @Test
    public void testSighashMatchesGoldenVector() {
        PSBT psbt = buildFixedPsbt(patternPublicKey());
        byte[] sighash = BtqPsbtSigner.sighash(psbt, 0);
        Assertions.assertEquals(GOLDEN_SIGHASH, HEX.formatHex(sighash),
                "drongo hashForTaprootSignature must match the BIP341 P2MR golden sighash");
    }

    @Test
    public void testFeeCalculation() {
        PSBT psbt = buildFixedPsbt(patternPublicKey());
        Assertions.assertEquals(10_000L, BtqPsbtSigner.feeSats(psbt)); //100000 in - 90000 out
    }

    @Test
    public void testSignVerifyFinalizeRoundTrip() throws Exception {
        //A real ML-DSA key: seed -> pubkey -> leaf -> spend -> sign -> verify -> finalize
        byte[] seed = new byte[Mldsa44.SEED_BYTES];
        for(int i = 0; i < seed.length; i++) {
            seed[i] = (byte)(0x30 + i);
        }
        byte[] pubKey = Mldsa44.publicKeyFromSeed(seed);
        PSBT psbt = buildFixedPsbt(pubKey);

        List<byte[]> sighashes = BtqPsbtSigner.sign(psbt, Map.of(0, seed));
        Assertions.assertEquals(1, sighashes.size());

        PSBTInput input = psbt.getPsbtInputs().get(0);
        Assertions.assertArrayEquals(pubKey, input.getP2mrDilithiumPubKey());
        Assertions.assertEquals(Mldsa44.TRANSACTION_SIGNATURE_BYTES, input.getP2mrDilithiumSignature().length);
        //The stored signature must verify against the stored sighash and public key
        Assertions.assertTrue(Mldsa44.verifyTransactionHash(pubKey, sighashes.get(0), input.getP2mrDilithiumSignature()));

        Transaction finalTx = BtqPsbtSigner.finalise(psbt);
        Assertions.assertTrue(finalTx.isSegwit());
        TransactionWitness witness = finalTx.getInputs().get(0).getWitness();
        Assertions.assertEquals(3, witness.getPushCount()); //[signature, leafScript, controlBlock]
        List<byte[]> pushes = witness.getPushes();
        Assertions.assertEquals(Mldsa44.TRANSACTION_SIGNATURE_BYTES, pushes.get(0).length);
        Assertions.assertArrayEquals(P2MR.singleKeyLeafScript(pubKey), pushes.get(1));
        Assertions.assertArrayEquals(P2MR.singleLeafControlBlock(), pushes.get(2));
        //Empty scriptSig for the witness input
        Assertions.assertEquals(0, finalTx.getInputs().get(0).getScriptBytes().length);
    }

    @Test
    public void testSignRejectsWrongKey() {
        //A seed whose pubkey does not commit to the input's leaf must be rejected
        PSBT psbt = buildFixedPsbt(patternPublicKey()); //leaf commits to the (non-derivable) pattern key
        byte[] wrongSeed = new byte[Mldsa44.SEED_BYTES];
        Arrays.fill(wrongSeed, (byte)0x7f);
        Assertions.assertThrows(IllegalStateException.class, () -> BtqPsbtSigner.sign(psbt, Map.of(0, wrongSeed)));
    }
}
