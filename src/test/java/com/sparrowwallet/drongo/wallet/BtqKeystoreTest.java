package com.sparrowwallet.drongo.wallet;

import com.sparrowwallet.drongo.KeyPurpose;
import com.sparrowwallet.drongo.Network;
import com.sparrowwallet.drongo.btq.Mldsa44;
import com.sparrowwallet.drongo.crypto.EncryptionType;
import com.sparrowwallet.drongo.crypto.Key;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

/**
 * Tests the BTQ custody keystore: creation, derivation caching, and the encrypt/decrypt lifecycle.
 * The global Network is deliberately left untouched (derivation-by-network is covered by
 * {@link com.sparrowwallet.drongo.btq.BtqDerivationTest}'s golden vectors).
 */
public class BtqKeystoreTest {
    private static byte[] master() {
        byte[] master = new byte[32];
        for(int i = 0; i < master.length; i++) {
            master[i] = (byte)(0x40 + i);
        }
        return master;
    }

    private static Key testKey() {
        byte[] keyBytes = new byte[32];
        Arrays.fill(keyBytes, (byte)0x55);
        return new Key(keyBytes, new byte[16], EncryptionType.Deriver.ARGON2);
    }

    @Test
    public void testFromBtqMasterSecret() throws InvalidKeystoreException {
        Keystore keystore = Keystore.fromBtqMasterSecret(master(), Network.get());
        Assertions.assertEquals(KeystoreSource.SW_BTQ_SEED, keystore.getSource());
        Assertions.assertEquals(WalletModel.BTQ_CORE, keystore.getWalletModel());
        Assertions.assertTrue(keystore.hasBtqMasterSecret());
        Assertions.assertTrue(keystore.hasPrivateKey());
        Assertions.assertFalse(keystore.hasMasterPrivateKey()); //not a BIP32 keystore
        Assertions.assertEquals(8, keystore.getKeyDerivation().getMasterFingerprint().length());
        keystore.checkKeystore(); //must not throw despite having no xpub
        Assertions.assertTrue(keystore.isValid());
    }

    @Test
    public void testBtqPublicKeyDerivationAndCache() {
        Keystore keystore = Keystore.fromBtqMasterSecret(master(), Network.get());
        byte[] receive0 = keystore.getBtqPublicKey(KeyPurpose.RECEIVE, 0);
        byte[] change0 = keystore.getBtqPublicKey(KeyPurpose.CHANGE, 0);
        Assertions.assertEquals(Mldsa44.PUBLIC_KEY_BYTES, receive0.length);
        Assertions.assertFalse(Arrays.equals(receive0, change0), "receive and change chains must derive independently");
        //Deterministic and cached
        Assertions.assertArrayEquals(receive0, keystore.getBtqPublicKey(KeyPurpose.RECEIVE, 0));

        //The key seed derives the same public key
        byte[] keySeed = keystore.getBtqKeySeed(KeyPurpose.RECEIVE, 0);
        Assertions.assertArrayEquals(receive0, Mldsa44.publicKeyFromSeed(keySeed));
    }

    @Test
    public void testEncryptDecryptLifecycle() throws InvalidKeystoreException {
        Keystore keystore = Keystore.fromBtqMasterSecret(master(), Network.get());
        byte[] receive0 = keystore.getBtqPublicKey(KeyPurpose.RECEIVE, 0);
        Key key = testKey();

        keystore.encrypt(key);
        Assertions.assertTrue(keystore.isEncrypted());
        keystore.checkKeystore(); //valid while encrypted
        //The pre-warmed cache keeps the gap window readable while locked
        Assertions.assertArrayEquals(receive0, keystore.getBtqPublicKey(KeyPurpose.RECEIVE, 0));
        Assertions.assertEquals(Mldsa44.PUBLIC_KEY_BYTES, keystore.getBtqPublicKey(KeyPurpose.RECEIVE, Keystore.BTQ_CACHE_WARM_INDEXES - 1).length);
        //Beyond the warmed window, new derivations require the secret
        Assertions.assertThrows(IllegalStateException.class, () -> keystore.getBtqPublicKey(KeyPurpose.RECEIVE, Keystore.BTQ_CACHE_WARM_INDEXES));
        Assertions.assertThrows(IllegalStateException.class, () -> keystore.getBtqKeySeed(KeyPurpose.RECEIVE, 0));

        keystore.decrypt(key);
        Assertions.assertFalse(keystore.isEncrypted());
        Assertions.assertArrayEquals(master(), keystore.getBtqMasterSecret().getSecret());
        //Derivation works again and matches
        Assertions.assertArrayEquals(receive0, keystore.getBtqPublicKey(KeyPurpose.RECEIVE, 0));
        Assertions.assertEquals(Mldsa44.PUBLIC_KEY_BYTES, keystore.getBtqPublicKey(KeyPurpose.RECEIVE, 1).length);
    }

    @Test
    public void testCopyAndClear() {
        Keystore keystore = Keystore.fromBtqMasterSecret(master(), Network.get());
        Keystore copy = keystore.copy();
        Assertions.assertTrue(copy.hasBtqMasterSecret());
        Assertions.assertArrayEquals(master(), copy.getBtqMasterSecret().getSecret());

        //Clearing the original must not affect the copy
        keystore.clearPrivate();
        Assertions.assertArrayEquals(new byte[32], keystore.getBtqMasterSecret().getSecret());
        Assertions.assertArrayEquals(master(), copy.getBtqMasterSecret().getSecret());
    }

    @Test
    public void testCheckKeystoreRejectsMissingSecret() {
        Keystore keystore = Keystore.fromBtqMasterSecret(master(), Network.get());
        keystore.setBtqMasterSecret(null);
        Assertions.assertThrows(InvalidKeystoreException.class, keystore::checkKeystore);
    }
}
