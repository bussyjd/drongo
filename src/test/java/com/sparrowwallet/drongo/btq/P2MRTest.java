package com.sparrowwallet.drongo.btq;

import com.sparrowwallet.drongo.Network;
import com.sparrowwallet.drongo.protocol.Script;
import com.sparrowwallet.drongo.protocol.ScriptType;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.HexFormat;

/**
 * Golden-vector tests for the single-key P2MR construction and the ML-DSA-44 primitive.
 * <p>
 * The expected Merkle root / script / addresses were produced by an independent Python reference of the
 * BIP341 TapLeaf + Bech32m algorithm (which mirrors the Qparrow implementation validated against BTQ Core
 * on public testnet). The deterministic input public key is byte[i] = i mod 256 over 1312 bytes.
 */
public class P2MRTest {
    private static final HexFormat HEX = HexFormat.of();

    private static byte[] patternPublicKey() {
        byte[] pubKey = new byte[Mldsa44.PUBLIC_KEY_BYTES];
        for(int i = 0; i < pubKey.length; i++) {
            pubKey[i] = (byte)(i & 0xff);
        }
        return pubKey;
    }

    private static final String MERKLE_ROOT_HEX = "24bb54c16f5d635ca0c844da9817aeb44aab1e661f4167f6cfb5e6116bddb248";
    private static final String SCRIPTPUBKEY_HEX = "522024bb54c16f5d635ca0c844da9817aeb44aab1e661f4167f6cfb5e6116bddb248";
    private static final String ADDR_TESTNET = "tbtq1zyja4fst0t434egxggndfs9awk392k8nxraqk0ak0khnpz67akfyqz23n49";
    private static final String ADDR_MAINNET = "qbtc1zyja4fst0t434egxggndfs9awk392k8nxraqk0ak0khnpz67akfyq8l6m0t";
    private static final String ADDR_SIGNET = "qtb1zyja4fst0t434egxggndfs9awk392k8nxraqk0ak0khnpz67akfyq58u5q4";
    private static final String ADDR_REGTEST = "qcrt1zyja4fst0t434egxggndfs9awk392k8nxraqk0ak0khnpz67akfyqr7vysz";

    @Test
    public void testSingleKeyLeafScript() {
        byte[] leaf = P2MR.singleKeyLeafScript(patternPublicKey());
        //OP_PUSHDATA2 (0x4d) + len 1312 little-endian (0x20 0x05) + 1312 pubkey bytes + OP_CHECKSIGDILITHIUM (0xbb)
        Assertions.assertEquals(1316, leaf.length);
        Assertions.assertEquals((byte)0x4d, leaf[0]);
        Assertions.assertEquals((byte)0x20, leaf[1]);
        Assertions.assertEquals((byte)0x05, leaf[2]);
        Assertions.assertEquals((byte)0xbb, leaf[leaf.length - 1]);
    }

    @Test
    public void testMerkleRootGoldenVector() {
        byte[] merkleRoot = P2MR.merkleRootForPublicKey(patternPublicKey());
        Assertions.assertEquals(MERKLE_ROOT_HEX, HEX.formatHex(merkleRoot));
    }

    @Test
    public void testOutputScriptGoldenVector() {
        byte[] merkleRoot = HEX.parseHex(MERKLE_ROOT_HEX);
        Assertions.assertEquals(SCRIPTPUBKEY_HEX, HEX.formatHex(P2MR.outputScript(merkleRoot)));
    }

    @Test
    public void testScriptTypeOutputScriptMatchesHelper() {
        byte[] merkleRoot = HEX.parseHex(MERKLE_ROOT_HEX);
        Script script = ScriptType.P2MR.getOutputScript(merkleRoot);
        Assertions.assertEquals(SCRIPTPUBKEY_HEX, HEX.formatHex(script.getProgram()));
    }

    @Test
    public void testScriptTypeRecognisesP2MR() {
        byte[] merkleRoot = HEX.parseHex(MERKLE_ROOT_HEX);
        Script script = new Script(HEX.parseHex(SCRIPTPUBKEY_HEX));
        Assertions.assertTrue(ScriptType.P2MR.isScriptType(script));
        Assertions.assertEquals(ScriptType.P2MR, ScriptType.getType(script));
        Assertions.assertArrayEquals(merkleRoot, ScriptType.P2MR.getHashFromScript(script));
    }

    @Test
    public void testAddressGoldenVectorPerNetwork() {
        byte[] pubKey = patternPublicKey();
        Assertions.assertEquals(ADDR_TESTNET, P2MR.addressForPublicKey(pubKey).getAddress(Network.TESTNET));
        Assertions.assertEquals(ADDR_MAINNET, P2MR.addressForPublicKey(pubKey).getAddress(Network.MAINNET));
        Assertions.assertEquals(ADDR_SIGNET, P2MR.addressForPublicKey(pubKey).getAddress(Network.SIGNET));
        Assertions.assertEquals(ADDR_REGTEST, P2MR.addressForPublicKey(pubKey).getAddress(Network.REGTEST));
    }

    @Test
    public void testScriptBundle() {
        P2MR.P2MRScript bundle = P2MR.scriptForPublicKey(Network.TESTNET, patternPublicKey());
        Assertions.assertEquals(MERKLE_ROOT_HEX, HEX.formatHex(bundle.merkleRoot()));
        Assertions.assertEquals(SCRIPTPUBKEY_HEX, HEX.formatHex(bundle.outputScript()));
        Assertions.assertEquals(ADDR_TESTNET, bundle.address());
        Assertions.assertArrayEquals(new byte[]{(byte)0xc1}, bundle.controlBlock());
        Assertions.assertEquals(1316, bundle.leafScript().length);
    }

    @Test
    public void testMldsaDeterministicAndVerifies() {
        byte[] seed = new byte[Mldsa44.SEED_BYTES];
        for(int i = 0; i < seed.length; i++) {
            seed[i] = (byte)(i + 1);
        }

        byte[] pubKey1 = Mldsa44.publicKeyFromSeed(seed);
        byte[] pubKey2 = Mldsa44.publicKeyFromSeed(seed);
        Assertions.assertEquals(Mldsa44.PUBLIC_KEY_BYTES, pubKey1.length);
        Assertions.assertArrayEquals(pubKey1, pubKey2, "ML-DSA-44 seed->pubkey must be deterministic");

        byte[] sighash = new byte[Mldsa44.TRANSACTION_HASH_BYTES];
        for(int i = 0; i < sighash.length; i++) {
            sighash[i] = (byte)(0xa0 + i);
        }
        byte[] txSignature = Mldsa44.signTransactionHash(seed, sighash);
        Assertions.assertEquals(Mldsa44.TRANSACTION_SIGNATURE_BYTES, txSignature.length);
        Assertions.assertEquals(Mldsa44.SIGHASH_ALL, txSignature[Mldsa44.SIGNATURE_BYTES]);
        Assertions.assertTrue(Mldsa44.verifyTransactionHash(pubKey1, sighash, txSignature));

        //A tampered signature must not verify
        txSignature[0] ^= 0x01;
        Assertions.assertFalse(Mldsa44.verifyTransactionHash(pubKey1, sighash, txSignature));
    }

    @Test
    public void testPublicKeyDerivesToStableAddress() {
        byte[] seed = new byte[Mldsa44.SEED_BYTES];
        seed[0] = 0x2a;
        byte[] pubKey = Mldsa44.publicKeyFromSeed(seed);
        String address1 = P2MR.addressForPublicKey(pubKey).getAddress(Network.TESTNET);
        String address2 = P2MR.addressForPublicKey(pubKey).getAddress(Network.TESTNET);
        Assertions.assertTrue(address1.startsWith("tbtq1z"));
        Assertions.assertEquals(address1, address2);
    }
}
