package com.sparrowwallet.drongo.wallet;

import com.sparrowwallet.drongo.KeyPurpose;
import com.sparrowwallet.drongo.Network;
import com.sparrowwallet.drongo.crypto.EncryptionType;
import com.sparrowwallet.drongo.crypto.Key;
import com.sparrowwallet.drongo.policy.Policy;
import com.sparrowwallet.drongo.policy.PolicyType;
import com.sparrowwallet.drongo.protocol.ScriptType;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

/** A locked BTQ wallet must never throw when the UI/history derive addresses across the gap window. */
public class BtqLockedDerivationTest {
    private static byte[] master() {
        byte[] m = new byte[32];
        for(int i = 0; i < m.length; i++) m[i] = (byte)(0x11 + i);
        return m;
    }

    private static Key key() {
        byte[] k = new byte[32];
        Arrays.fill(k, (byte)0x55);
        return new Key(k, new byte[16], EncryptionType.Deriver.ARGON2);
    }

    @Test
    public void testLockedWalletDerivesWithinCacheAndNullsBeyond() {
        Wallet wallet = new Wallet("locked-btq");
        wallet.setPolicyType(PolicyType.SINGLE_MLDSA);
        wallet.setScriptType(ScriptType.P2MR);
        Keystore keystore = Keystore.fromBtqMasterSecret(master(), Network.get());
        wallet.getKeystores().add(keystore);
        wallet.setDefaultPolicy(Policy.getPolicy(PolicyType.SINGLE_MLDSA, ScriptType.P2MR, wallet.getKeystores(), 1));

        //Cache the used address (index 0), then lock
        byte[] used = keystore.getBtqPublicKey(KeyPurpose.RECEIVE, 0);
        Assertions.assertNotNull(used);
        keystore.encrypt(key());
        Assertions.assertTrue(wallet.isEncrypted());

        //A cached (used) node still yields an address; an uncached far node yields null, never throws
        WalletNode receive0 = new WalletNode(wallet, KeyPurpose.RECEIVE, 0);
        WalletNode receiveFar = new WalletNode(wallet, KeyPurpose.RECEIVE, 5000);
        Assertions.assertNotNull(wallet.getAddress(receive0));
        Assertions.assertNull(wallet.getAddress(receiveFar));
        Assertions.assertNull(wallet.getOutputScript(receiveFar));
        Assertions.assertNull(wallet.getOutputDescriptor(receiveFar));

        //fillToIndex over the whole gap window must not throw on a locked wallet
        Assertions.assertDoesNotThrow(() -> wallet.getNode(KeyPurpose.RECEIVE).fillToIndex(wallet, 4000));
    }
}
