package com.sparrowwallet.drongo.psbt;

import com.sparrowwallet.drongo.btq.Mldsa44;
import com.sparrowwallet.drongo.btq.P2MR;
import com.sparrowwallet.drongo.protocol.Script;
import com.sparrowwallet.drongo.protocol.ScriptType;
import com.sparrowwallet.drongo.protocol.Sha256Hash;
import com.sparrowwallet.drongo.protocol.Transaction;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

/**
 * Round-trip tests for the Bitcoin Quantum P2MR PSBT input fields (BIP360: 0x19 leaf script, 0x1a merkle
 * root, 0x1b Dilithium script sig). drongo's parser drops unrecognised input key types, so these fields
 * must be explicitly parsed and re-serialised to survive a PSBT round-trip.
 */
public class P2MRPsbtInputTest {
    private static byte[] patternPublicKey() {
        byte[] pubKey = new byte[Mldsa44.PUBLIC_KEY_BYTES];
        for(int i = 0; i < pubKey.length; i++) {
            pubKey[i] = (byte)(i & 0xff);
        }
        return pubKey;
    }

    private static PSBT buildP2mrPsbt(byte[] pubKey, byte[] signature) {
        byte[] leafScript = P2MR.singleKeyLeafScript(pubKey);
        byte[] merkleRoot = P2MR.merkleRootForPublicKey(pubKey);

        byte[] prevHash = new byte[32];
        Arrays.fill(prevHash, (byte)0x11);
        Transaction tx = new Transaction();
        tx.addInput(Sha256Hash.wrap(prevHash), 0, new Script(new byte[0]));
        tx.addOutput(50_000L, ScriptType.P2MR.getOutputScript(merkleRoot));

        PSBT psbt = new PSBT(tx);
        PSBTInput input = psbt.getPsbtInputs().get(0);
        input.setP2mrLeaf(leafScript, (byte)P2MR.LEAF_VERSION, P2MR.singleLeafControlBlock());
        input.setP2mrMerkleRoot(merkleRoot);
        input.setP2mrDilithiumSignature(pubKey, merkleRoot, signature);
        return psbt;
    }

    private static byte[] fillerSignature() {
        byte[] signature = new byte[Mldsa44.TRANSACTION_SIGNATURE_BYTES];
        for(int i = 0; i < Mldsa44.SIGNATURE_BYTES; i++) {
            signature[i] = (byte)((i * 7) & 0xff);
        }
        signature[Mldsa44.SIGNATURE_BYTES] = Mldsa44.SIGHASH_ALL;
        return signature;
    }

    @Test
    public void testP2mrFieldsSurviveRoundTrip() throws PSBTParseException {
        byte[] pubKey = patternPublicKey();
        byte[] signature = fillerSignature();
        byte[] merkleRoot = P2MR.merkleRootForPublicKey(pubKey);
        byte[] leafScript = P2MR.singleKeyLeafScript(pubKey);

        PSBT original = buildP2mrPsbt(pubKey, signature);
        byte[] serialized = original.serialize();

        PSBT reparsed = new PSBT(serialized, false);
        PSBTInput input = reparsed.getPsbtInputs().get(0);

        Assertions.assertArrayEquals(leafScript, input.getP2mrLeafScript());
        Assertions.assertEquals((byte)P2MR.LEAF_VERSION, input.getP2mrLeafVersion());
        Assertions.assertArrayEquals(new byte[]{(byte)P2MR.CONTROL_BYTE}, input.getP2mrControlBlock());
        Assertions.assertArrayEquals(merkleRoot, input.getP2mrMerkleRoot());
        Assertions.assertArrayEquals(pubKey, input.getP2mrDilithiumPubKey());
        Assertions.assertArrayEquals(merkleRoot, input.getP2mrDilithiumLeafHash());
        Assertions.assertArrayEquals(signature, input.getP2mrDilithiumSignature());
    }

    @Test
    public void testReserializationIsByteIdentical() throws PSBTParseException {
        PSBT original = buildP2mrPsbt(patternPublicKey(), fillerSignature());
        byte[] first = original.serialize();
        byte[] second = new PSBT(first, false).serialize();
        Assertions.assertArrayEquals(first, second, "P2MR PSBT must re-serialize byte-identically");
    }

    @Test
    public void testP2mrOutputScriptRecognisedInPsbt() throws PSBTParseException {
        PSBT psbt = buildP2mrPsbt(patternPublicKey(), fillerSignature());
        Transaction tx = new PSBT(psbt.serialize(), false).getTransaction();
        Script outputScript = tx.getOutputs().get(0).getScript();
        Assertions.assertEquals(ScriptType.P2MR, ScriptType.getType(outputScript));
    }

    @Test
    public void testRejectsBadSignatureLength() throws PSBTParseException {
        //A P2MR Dilithium signature of the wrong length must be rejected on parse
        byte[] shortSig = new byte[Mldsa44.TRANSACTION_SIGNATURE_BYTES - 1];
        PSBT psbt = buildP2mrPsbt(patternPublicKey(), fillerSignature());
        //Force an invalid signature length directly, then serialise and expect parse rejection
        psbt.getPsbtInputs().get(0).setP2mrDilithiumSignature(patternPublicKey(),
                P2MR.merkleRootForPublicKey(patternPublicKey()), shortSig);
        byte[] serialized = psbt.serialize();
        Assertions.assertThrows(PSBTParseException.class, () -> new PSBT(serialized, false));
    }
}
