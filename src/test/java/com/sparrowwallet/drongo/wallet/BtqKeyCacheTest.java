package com.sparrowwallet.drongo.wallet;

import com.sparrowwallet.drongo.KeyPurpose;
import com.sparrowwallet.drongo.Network;
import com.sparrowwallet.drongo.crypto.EncryptionType;
import com.sparrowwallet.drongo.crypto.Key;
import com.sparrowwallet.drongo.policy.Policy;
import com.sparrowwallet.drongo.policy.PolicyType;
import com.sparrowwallet.drongo.protocol.ScriptType;
import com.sparrowwallet.drongo.protocol.Sha256Hash;
import com.sparrowwallet.drongo.protocol.Transaction;
import com.sparrowwallet.drongo.protocol.Script;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.Date;
import java.util.TreeSet;

/**
 * The ML-DSA public key cache lifecycle across encryption: usage-aware growth on decrypt, merge-back
 * from a decrypted signing copy, and codec safety for sparse caches.
 */
public class BtqKeyCacheTest {
    private static byte[] master() {
        byte[] master = new byte[32];
        for(int i = 0; i < master.length; i++) {
            master[i] = (byte)(0x60 + i);
        }
        return master;
    }

    private static Key key() {
        byte[] k = new byte[32];
        java.util.Arrays.fill(k, (byte)0x11);
        return new Key(k, new byte[16], EncryptionType.Deriver.ARGON2);
    }

    private static Wallet buildWallet() {
        Wallet wallet = new Wallet("BTQ Cache Wallet");
        wallet.setPolicyType(PolicyType.SINGLE_MLDSA);
        wallet.setScriptType(ScriptType.P2MR);
        wallet.getKeystores().add(Keystore.fromBtqMasterSecret(master(), Network.get()));
        wallet.setDefaultPolicy(Policy.getPolicy(PolicyType.SINGLE_MLDSA, ScriptType.P2MR, wallet.getKeystores(), 1));
        return wallet;
    }

    /** Mark the given receive index as used by recording a wallet transaction output at it. */
    private static void markUsed(Wallet wallet, int index) {
        wallet.getNode(KeyPurpose.RECEIVE).fillToIndex(wallet, index);
        WalletNode node = wallet.getNode(KeyPurpose.RECEIVE).getChildren().stream()
                .filter(child -> child.getIndex() == index).findFirst().orElseThrow();
        Script nodeScript = wallet.getOutputScript(node);
        byte[] prevHash = new byte[32];
        java.util.Arrays.fill(prevHash, (byte)0x55);
        Transaction fundingTx = new Transaction();
        fundingTx.setVersion(2);
        fundingTx.addInput(Sha256Hash.wrap(prevHash), 0, new Script(new byte[0]));
        fundingTx.addOutput(50_000L, nodeScript);
        BlockTransaction fundingBlockTx = new BlockTransaction(fundingTx.getTxId(), 100, new Date(1_700_000_000_000L), 0L, fundingTx);
        wallet.updateTransactions(java.util.Map.of(fundingTx.getTxId(), fundingBlockTx));
        TreeSet<BlockTransactionHashIndex> txos = new TreeSet<>();
        txos.add(new BlockTransactionHashIndex(fundingTx.getTxId(), 100, fundingBlockTx.getDate(), 0L, 0, 50_000L));
        node.updateTransactionOutputs(wallet, txos);
    }

    @Test
    public void testDecryptGrowsCacheToLookAheadWindow() {
        Wallet wallet = buildWallet();
        markUsed(wallet, 15); //look-ahead window now extends to index 15 + gap limit

        wallet.encrypt(key());
        Assertions.assertTrue(wallet.isEncrypted());

        wallet.decrypt(key());
        Keystore keystore = wallet.getKeystores().get(0);
        int expected = 15 + wallet.getGapLimit();
        Assertions.assertNotNull(keystore.getBtqPublicKey(KeyPurpose.RECEIVE, expected),
                "decrypt must warm the cache to the look-ahead window (index " + expected + ")");

        //And the grown cache must survive re-encryption (locked derivation within the window)
        wallet.encrypt(key());
        Assertions.assertNotNull(keystore.getBtqPublicKey(KeyPurpose.RECEIVE, expected),
                "grown cache must remain available while locked");
    }

    @Test
    public void testMergeCacheFromDecryptedCopy() {
        Wallet wallet = buildWallet();
        wallet.encrypt(key());

        Wallet copy = wallet.copy();
        copy.decrypt(key());
        Keystore copyKeystore = copy.getKeystores().get(0);
        byte[] extraKey = copyKeystore.getBtqPublicKey(KeyPurpose.CHANGE, 30); //derives on the unlocked copy
        Assertions.assertNotNull(extraKey);

        Keystore original = wallet.getKeystores().get(0);
        Assertions.assertNull(original.getBtqPublicKey(KeyPurpose.CHANGE, 30), "locked original cannot derive index 30");

        Assertions.assertTrue(original.mergeBtqPublicKeyCache(copyKeystore), "merge must add the new key");
        Assertions.assertArrayEquals(extraKey, original.getBtqPublicKey(KeyPurpose.CHANGE, 30));
        Assertions.assertFalse(original.mergeBtqPublicKeyCache(copyKeystore), "second merge must be a no-op");
    }

    @Test
    public void testSparseCacheEncodesContiguousPrefixOnly() {
        Wallet wallet = buildWallet();
        Keystore keystore = wallet.getKeystores().get(0);
        byte[] key20 = keystore.getBtqPublicKey(KeyPurpose.RECEIVE, 20);
        byte[] sparseKey = keystore.getBtqPublicKey(KeyPurpose.RECEIVE, 40); //leaves a hole at 21..39
        Assertions.assertNotNull(sparseKey);

        byte[] encoded = keystore.encodeBtqPublicKeyCache();
        Keystore restored = new Keystore(); //no master secret: can only serve what the codec restored
        restored.decodeBtqPublicKeyCache(encoded);

        //The contiguous prefix decodes at the right indexes; the sparse tail is dropped, never re-indexed
        Assertions.assertArrayEquals(key20, restored.getBtqPublicKey(KeyPurpose.RECEIVE, 20));
        Assertions.assertNull(restored.getBtqPublicKey(KeyPurpose.RECEIVE, 21),
                "the hole must stay a hole - a re-indexed sparse tail would surface the wrong key here");
        Assertions.assertNull(restored.getBtqPublicKey(KeyPurpose.RECEIVE, 40),
                "the sparse tail past the hole is dropped by the positional codec");
    }
}
