package com.sparrowwallet.drongo.wallet;

import com.sparrowwallet.drongo.KeyPurpose;
import com.sparrowwallet.drongo.Network;
import com.sparrowwallet.drongo.btq.P2MR;
import com.sparrowwallet.drongo.address.Address;
import com.sparrowwallet.drongo.address.P2MRAddress;
import com.sparrowwallet.drongo.policy.Policy;
import com.sparrowwallet.drongo.policy.PolicyType;
import com.sparrowwallet.drongo.protocol.Script;
import com.sparrowwallet.drongo.protocol.ScriptType;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.List;

/** Tests a Bitcoin Quantum wallet: SINGLE_MLDSA policy + P2MR script type + a SW_BTQ_SEED keystore. */
public class BtqWalletTest {
    private static byte[] master() {
        byte[] master = new byte[32];
        for(int i = 0; i < master.length; i++) {
            master[i] = (byte)(0x60 + i);
        }
        return master;
    }

    private static Wallet buildWallet() {
        Wallet wallet = new Wallet("BTQ Wallet");
        wallet.setPolicyType(PolicyType.SINGLE_MLDSA);
        wallet.setScriptType(ScriptType.P2MR);
        Keystore keystore = Keystore.fromBtqMasterSecret(master(), Network.get());
        wallet.getKeystores().add(keystore);
        wallet.setDefaultPolicy(Policy.getPolicy(PolicyType.SINGLE_MLDSA, ScriptType.P2MR, wallet.getKeystores(), 1));
        return wallet;
    }

    @Test
    public void testAddressGeneration() {
        Wallet wallet = buildWallet();
        WalletNode receive0 = new WalletNode(wallet, KeyPurpose.RECEIVE, 0);
        Address address = wallet.getAddress(receive0);
        Assertions.assertInstanceOf(P2MRAddress.class, address);

        //Must match the direct construction from the keystore's derived public key
        byte[] pubKey = wallet.getKeystores().get(0).getBtqPublicKey(KeyPurpose.RECEIVE, 0);
        Assertions.assertEquals(P2MR.addressForPublicKey(pubKey).getAddress(Network.get()), address.getAddress(Network.get()));

        //Receive and change nodes derive different addresses; derivation is stable
        WalletNode change0 = new WalletNode(wallet, KeyPurpose.CHANGE, 0);
        Assertions.assertNotEquals(address.getAddress(Network.get()), wallet.getAddress(change0).getAddress(Network.get()));
        Assertions.assertEquals(address.getAddress(Network.get()), wallet.getAddress(receive0).getAddress(Network.get()));
    }

    @Test
    public void testOutputScriptMatchesAddress() {
        Wallet wallet = buildWallet();
        WalletNode receive0 = new WalletNode(wallet, KeyPurpose.RECEIVE, 0);
        Script outputScript = wallet.getOutputScript(receive0);
        Assertions.assertEquals(ScriptType.P2MR, ScriptType.getType(outputScript));
        Assertions.assertArrayEquals(wallet.getAddress(receive0).getOutputScript().getProgram(), outputScript.getProgram());
    }

    @Test
    public void testOutputDescriptorIsAddrForm() {
        Wallet wallet = buildWallet();
        WalletNode receive0 = new WalletNode(wallet, KeyPurpose.RECEIVE, 0);
        String descriptor = wallet.getOutputDescriptor(receive0);
        Assertions.assertEquals("addr(" + wallet.getAddress(receive0) + ")", descriptor);
    }

    @Test
    public void testPolicyConstruction() {
        //Must not throw, and P2MR must be addressable only for SINGLE_MLDSA
        Policy policy = Policy.getPolicy(PolicyType.SINGLE_MLDSA, ScriptType.P2MR, buildWallet().getKeystores(), 1);
        Assertions.assertNotNull(policy.getMiniscript());

        List<ScriptType> mldsaTypes = ScriptType.getAddressableScriptTypes(PolicyType.SINGLE_MLDSA);
        Assertions.assertEquals(List.of(ScriptType.P2MR), mldsaTypes);
        Assertions.assertFalse(ScriptType.getAddressableScriptTypes(PolicyType.SINGLE_HD).contains(ScriptType.P2MR),
                "P2MR must not appear for Bitcoin policy types");
        Assertions.assertFalse(ScriptType.getAddressableScriptTypes(PolicyType.MULTI_HD).contains(ScriptType.P2MR));
    }

    @Test
    public void testInputVbytes() {
        //BTQ single-key P2MR input: 4402 WU at witness scale 16 = 275.125 vbytes
        Assertions.assertEquals(275.125, ScriptType.P2MR.getInputVbytes(), 0.0001);
    }
}
