package com.sparrowwallet.drongo.btq;

import com.sparrowwallet.drongo.protocol.Script;
import com.sparrowwallet.drongo.protocol.Sha256Hash;
import com.sparrowwallet.drongo.protocol.Transaction;
import com.sparrowwallet.drongo.protocol.TransactionOutput;
import com.sparrowwallet.drongo.protocol.TransactionWitness;
import com.sparrowwallet.drongo.psbt.PSBT;
import com.sparrowwallet.drongo.psbt.PSBTInput;
import com.sparrowwallet.drongo.psbt.PSBTSignatureException;
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

    private static byte[] testSeed(int offset) {
        byte[] seed = new byte[Mldsa44.SEED_BYTES];
        for(int i = 0; i < seed.length; i++) {
            seed[i] = (byte)(offset + i);
        }
        return seed;
    }

    /** A copy of the fixed PSBT for the seed's key, signed and finalized as a co-signer or Core would return it. */
    private static PSBT finalizedPsbt(byte[] seed) {
        PSBT psbt = buildFixedPsbt(Mldsa44.publicKeyFromSeed(seed));
        BtqPsbtSigner.sign(psbt, Map.of(0, seed));
        BtqPsbtSigner.finaliseInputs(psbt);
        return psbt;
    }

    private static void replaceWitness(PSBT psbt, byte[] signature, byte[] leafScript, byte[] controlBlock) {
        psbt.getPsbtInputs().get(0).setFinalScriptWitness(new TransactionWitness(psbt.getTransaction(), List.of(signature, leafScript, controlBlock)));
    }

    @Test
    public void testVerifyFinalizedSignaturesAcceptsSignedP2mr() throws Exception {
        byte[] seed = testSeed(0x30);
        PSBT open = buildFixedPsbt(Mldsa44.publicKeyFromSeed(seed));
        open.verifyFinalizedSignatures(finalizedPsbt(seed));
    }

    @Test
    public void testVerifyFinalizedSignaturesRejectsTamperedSignature() {
        byte[] seed = testSeed(0x30);
        PSBT open = buildFixedPsbt(Mldsa44.publicKeyFromSeed(seed));
        PSBT finalized = finalizedPsbt(seed);
        List<byte[]> pushes = finalized.getPsbtInputs().get(0).getFinalScriptWitness().getPushes();
        byte[] signature = pushes.get(0).clone();
        signature[100] ^= 0x01;
        replaceWitness(finalized, signature, pushes.get(1), pushes.get(2));
        PSBTSignatureException e = Assertions.assertThrows(PSBTSignatureException.class, () -> open.verifyFinalizedSignatures(finalized));
        Assertions.assertTrue(e.getMessage().contains("does not verify"), e.getMessage());
    }

    @Test
    public void testVerifyFinalizedSignaturesRejectsWrongSighashType() {
        byte[] seed = testSeed(0x30);
        PSBT open = buildFixedPsbt(Mldsa44.publicKeyFromSeed(seed));
        PSBT finalized = finalizedPsbt(seed);
        List<byte[]> pushes = finalized.getPsbtInputs().get(0).getFinalScriptWitness().getPushes();
        byte[] signature = pushes.get(0).clone();
        signature[Mldsa44.SIGNATURE_BYTES] = 0x03; //SIGHASH_SINGLE
        replaceWitness(finalized, signature, pushes.get(1), pushes.get(2));
        Assertions.assertThrows(PSBTSignatureException.class, () -> open.verifyFinalizedSignatures(finalized));
    }

    @Test
    public void testVerifyFinalizedSignaturesRejectsLeafTheUtxoDoesNotCommitTo() {
        //A valid signature by another key, presented with that key's leaf, must not be copied over this input's UTXO
        byte[] seed = testSeed(0x30);
        byte[] otherSeed = testSeed(0x50);
        PSBT open = buildFixedPsbt(Mldsa44.publicKeyFromSeed(seed));
        PSBT finalized = finalizedPsbt(seed);
        byte[] otherLeaf = P2MR.singleKeyLeafScript(Mldsa44.publicKeyFromSeed(otherSeed));
        byte[] otherSignature = Mldsa44.signTransactionHash(otherSeed, BtqPsbtSigner.sighash(open, 0, otherLeaf));
        replaceWitness(finalized, otherSignature, otherLeaf, P2MR.singleLeafControlBlock());
        PSBTSignatureException e = Assertions.assertThrows(PSBTSignatureException.class, () -> open.verifyFinalizedSignatures(finalized));
        Assertions.assertTrue(e.getMessage().contains("does not commit"), e.getMessage());
    }

    @Test
    public void testVerifyFinalizedSignaturesRejectsMultiLeafControlBlock() {
        byte[] seed = testSeed(0x30);
        PSBT open = buildFixedPsbt(Mldsa44.publicKeyFromSeed(seed));
        PSBT finalized = finalizedPsbt(seed);
        List<byte[]> pushes = finalized.getPsbtInputs().get(0).getFinalScriptWitness().getPushes();
        byte[] controlBlock = new byte[33];
        controlBlock[0] = P2MR.singleLeafControlBlock()[0];
        replaceWitness(finalized, pushes.get(0), pushes.get(1), controlBlock);
        Assertions.assertThrows(PSBTSignatureException.class, () -> open.verifyFinalizedSignatures(finalized));
    }

    @Test
    public void testVerifyFinalizedSignaturesRejectsNonCanonicalLeaf() {
        byte[] seed = testSeed(0x30);
        PSBT open = buildFixedPsbt(Mldsa44.publicKeyFromSeed(seed));
        PSBT finalized = finalizedPsbt(seed);
        List<byte[]> pushes = finalized.getPsbtInputs().get(0).getFinalScriptWitness().getPushes();
        byte[] leaf = pushes.get(1).clone();
        leaf[leaf.length - 1] = (byte)0xac; //OP_CHECKSIG in place of OP_CHECKSIGDILITHIUM
        replaceWitness(finalized, pushes.get(0), leaf, pushes.get(2));
        Assertions.assertThrows(PSBTSignatureException.class, () -> open.verifyFinalizedSignatures(finalized));
        Assertions.assertNull(P2MR.publicKeyFromSingleKeyLeafScript(leaf));
        Assertions.assertArrayEquals(Mldsa44.publicKeyFromSeed(seed), P2MR.publicKeyFromSingleKeyLeafScript(pushes.get(1)));
    }

    /** The fixed PSBT for the seed's key carrying its BIP360 0x1b Dilithium signature, as a co-signer or Core would return it unfinalized. */
    private static PSBT signedPsbt(byte[] seed) {
        PSBT psbt = buildFixedPsbt(Mldsa44.publicKeyFromSeed(seed));
        BtqPsbtSigner.sign(psbt, Map.of(0, seed));
        return psbt;
    }

    private static void tamperDilithiumSignature(PSBT psbt) {
        PSBTInput input = psbt.getPsbtInputs().get(0);
        byte[] signature = input.getP2mrDilithiumSignature().clone();
        signature[100] ^= 0x01;
        input.setP2mrDilithiumSignature(input.getP2mrDilithiumPubKey(), input.getP2mrDilithiumLeafHash(), signature);
    }

    @Test
    public void testParseVerifiesDilithiumSignature() throws Exception {
        PSBT parsed = new PSBT(signedPsbt(testSeed(0x30)).serialize(), true);
        Assertions.assertTrue(parsed.getPsbtInputs().get(0).isSigned());
    }

    @Test
    public void testParseRejectsTamperedDilithiumSignature() {
        PSBT signed = signedPsbt(testSeed(0x30));
        tamperDilithiumSignature(signed);
        byte[] serialized = signed.serialize();
        PSBTSignatureException e = Assertions.assertThrows(PSBTSignatureException.class, () -> new PSBT(serialized, true));
        Assertions.assertTrue(e.getMessage().contains("does not verify"), e.getMessage());
    }

    @Test
    public void testParseRejectsDilithiumSignatureForAnotherLeaf() {
        //The 0x1b key must name the leaf hash of the input's own leaf script
        byte[] seed = testSeed(0x30);
        PSBT signed = signedPsbt(seed);
        PSBTInput input = signed.getPsbtInputs().get(0);
        byte[] otherLeafHash = P2MR.tapLeafHash(P2MR.singleKeyLeafScript(Mldsa44.publicKeyFromSeed(testSeed(0x50))));
        input.setP2mrDilithiumSignature(input.getP2mrDilithiumPubKey(), otherLeafHash, input.getP2mrDilithiumSignature());
        byte[] serialized = signed.serialize();
        PSBTSignatureException e = Assertions.assertThrows(PSBTSignatureException.class, () -> new PSBT(serialized, true));
        Assertions.assertTrue(e.getMessage().contains("leaf other than"), e.getMessage());
    }

    @Test
    public void testParseRejectsLeafTheUtxoDoesNotCommitTo() {
        PSBT psbt = buildFixedPsbt(Mldsa44.publicKeyFromSeed(testSeed(0x30)));
        byte[] otherLeaf = P2MR.singleKeyLeafScript(Mldsa44.publicKeyFromSeed(testSeed(0x50)));
        psbt.getPsbtInputs().get(0).setP2mrLeaf(otherLeaf, (byte)P2MR.LEAF_VERSION, P2MR.singleLeafControlBlock());
        byte[] serialized = psbt.serialize();
        Assertions.assertThrows(com.sparrowwallet.drongo.psbt.PSBTParseException.class, () -> new PSBT(serialized, false));
    }

    @Test
    public void testParseRejectsMerkleRootTheUtxoDoesNotCommitTo() {
        PSBT psbt = buildFixedPsbt(Mldsa44.publicKeyFromSeed(testSeed(0x30)));
        psbt.getPsbtInputs().get(0).setP2mrMerkleRoot(new byte[32]);
        byte[] serialized = psbt.serialize();
        Assertions.assertThrows(com.sparrowwallet.drongo.psbt.PSBTParseException.class, () -> new PSBT(serialized, false));
    }

    @Test
    public void testCombineAcceptsCosignerDilithiumSignature() throws Exception {
        byte[] seed = testSeed(0x30);
        PSBT open = buildFixedPsbt(Mldsa44.publicKeyFromSeed(seed));
        PSBT combined = open.verifyCombinedSignatures(signedPsbt(seed));
        Assertions.assertTrue(combined.getPsbtInputs().get(0).isSigned());
    }

    @Test
    public void testCombineRejectsTamperedDilithiumSignature() {
        byte[] seed = testSeed(0x30);
        PSBT open = buildFixedPsbt(Mldsa44.publicKeyFromSeed(seed));
        PSBT signed = signedPsbt(seed);
        tamperDilithiumSignature(signed);
        PSBTSignatureException e = Assertions.assertThrows(PSBTSignatureException.class, () -> open.verifyCombinedSignatures(signed));
        Assertions.assertTrue(e.getMessage().contains("does not verify"), e.getMessage());
    }

    @Test
    public void testCombineRejectsReplacedLeafScript() {
        //A combine must not swap the leaf the open PSBT is collecting a signature over, even for one the other party has signed
        byte[] seed = testSeed(0x30);
        byte[] otherSeed = testSeed(0x50);
        PSBT open = buildFixedPsbt(Mldsa44.publicKeyFromSeed(seed));
        PSBT other = open.copy();
        other.getPsbtInputs().get(0).setP2mrLeaf(P2MR.singleKeyLeafScript(Mldsa44.publicKeyFromSeed(otherSeed)), (byte)P2MR.LEAF_VERSION, P2MR.singleLeafControlBlock());
        PSBTSignatureException e = Assertions.assertThrows(PSBTSignatureException.class, () -> open.verifyCombinedSignatures(other));
        Assertions.assertTrue(e.getMessage().contains("P2MR leaf script"), e.getMessage());
    }

    @Test
    public void testCombineRejectsReplacedMerkleRoot() {
        PSBT open = buildFixedPsbt(Mldsa44.publicKeyFromSeed(testSeed(0x30)));
        PSBT other = open.copy();
        other.getPsbtInputs().get(0).setP2mrMerkleRoot(new byte[32]);
        PSBTSignatureException e = Assertions.assertThrows(PSBTSignatureException.class, () -> open.verifyCombinedSignatures(other));
        Assertions.assertTrue(e.getMessage().contains("merkle root"), e.getMessage());
    }

    @Test
    public void testMerkleRootFromControlBlockFoldsSortedBranches() {
        byte[] leafA = P2MR.singleKeyLeafScript(Mldsa44.publicKeyFromSeed(testSeed(0x30)));
        byte[] leafB = P2MR.singleKeyLeafScript(Mldsa44.publicKeyFromSeed(testSeed(0x50)));
        byte[] hashA = P2MR.tapLeafHash(leafA);
        byte[] hashB = P2MR.tapLeafHash(leafB);
        byte[] root = P2MR.tapBranchHash(hashA, hashB);
        Assertions.assertArrayEquals(root, P2MR.tapBranchHash(hashB, hashA));

        byte[] controlA = new byte[33];
        controlA[0] = (byte)P2MR.CONTROL_BYTE;
        System.arraycopy(hashB, 0, controlA, 1, 32);
        byte[] controlB = new byte[33];
        controlB[0] = (byte)P2MR.CONTROL_BYTE;
        System.arraycopy(hashA, 0, controlB, 1, 32);
        Assertions.assertArrayEquals(root, P2MR.merkleRootFromControlBlock(leafA, controlA));
        Assertions.assertArrayEquals(root, P2MR.merkleRootFromControlBlock(leafB, controlB));
        Assertions.assertArrayEquals(hashA, P2MR.merkleRootFromControlBlock(leafA, P2MR.singleLeafControlBlock()));

        //BIP360 requires the parity bit, and a control block is one byte plus whole 32-byte nodes
        byte[] noParity = controlA.clone();
        noParity[0] = (byte)P2MR.LEAF_VERSION;
        Assertions.assertNull(P2MR.merkleRootFromControlBlock(leafA, noParity));
        Assertions.assertNull(P2MR.merkleRootFromControlBlock(leafA, Arrays.copyOf(controlA, 32)));
        Assertions.assertNull(P2MR.merkleRootFromControlBlock(leafA, new byte[0]));
    }

    @Test
    public void testParseVerifiesDilithiumSignatureInMultiLeafTree() throws Exception {
        //A signature over one leaf of a two-leaf tree verifies once the control block proves that leaf to the UTXO's root
        byte[] seed = testSeed(0x30);
        byte[] pubKey = Mldsa44.publicKeyFromSeed(seed);
        byte[] leafA = P2MR.singleKeyLeafScript(pubKey);
        byte[] hashB = P2MR.tapLeafHash(P2MR.singleKeyLeafScript(Mldsa44.publicKeyFromSeed(testSeed(0x50))));
        byte[] root = P2MR.tapBranchHash(P2MR.tapLeafHash(leafA), hashB);
        byte[] controlA = new byte[33];
        controlA[0] = (byte)P2MR.CONTROL_BYTE;
        System.arraycopy(hashB, 0, controlA, 1, 32);

        PSBT psbt = buildFixedPsbt(pubKey);
        PSBTInput input = psbt.getPsbtInputs().get(0);
        Script treeScript = new Script(P2MR.outputScript(root));
        input.setWitnessUtxo(new TransactionOutput(psbt.getTransaction(), 100_000L, treeScript));
        input.setP2mrLeaf(leafA, (byte)P2MR.LEAF_VERSION, controlA);
        input.setP2mrMerkleRoot(root);
        BtqPsbtSigner.sign(psbt, Map.of(0, seed));

        PSBT parsed = new PSBT(psbt.serialize(), true);
        Assertions.assertTrue(parsed.getPsbtInputs().get(0).isSigned());
    }
}
