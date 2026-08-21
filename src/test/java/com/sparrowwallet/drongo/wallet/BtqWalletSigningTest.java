package com.sparrowwallet.drongo.wallet;

import com.sparrowwallet.drongo.KeyPurpose;
import com.sparrowwallet.drongo.Network;
import com.sparrowwallet.drongo.btq.BtqPsbtSigner;
import com.sparrowwallet.drongo.btq.Mldsa44;
import com.sparrowwallet.drongo.btq.P2MR;
import com.sparrowwallet.drongo.policy.Policy;
import com.sparrowwallet.drongo.policy.PolicyType;
import com.sparrowwallet.drongo.protocol.Script;
import com.sparrowwallet.drongo.protocol.ScriptType;
import com.sparrowwallet.drongo.protocol.Sha256Hash;
import com.sparrowwallet.drongo.protocol.Transaction;
import com.sparrowwallet.drongo.protocol.TransactionOutput;
import com.sparrowwallet.drongo.protocol.TransactionSignature;
import com.sparrowwallet.drongo.protocol.TransactionWitness;
import com.sparrowwallet.drongo.psbt.PSBT;
import com.sparrowwallet.drongo.psbt.PSBTInput;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Map;

/**
 * End-to-end wallet-level signing: a SINGLE_MLDSA wallet signs and finalizes a PSBT that carries only
 * the witness UTXO - the exact shape BTQ Core's watch-only wallet produces (no 0x19/0x1a fields) -
 * proving Wallet.sign supplies the leaf/root itself before ML-DSA signing.
 */
public class BtqWalletSigningTest {
    private static byte[] master() {
        byte[] master = new byte[32];
        for(int i = 0; i < master.length; i++) {
            master[i] = (byte)(0x70 + i);
        }
        return master;
    }

    private static Wallet buildWallet() {
        Wallet wallet = new Wallet("BTQ Signing Wallet");
        wallet.setPolicyType(PolicyType.SINGLE_MLDSA);
        wallet.setScriptType(ScriptType.P2MR);
        wallet.getKeystores().add(Keystore.fromBtqMasterSecret(master(), Network.get()));
        wallet.setDefaultPolicy(Policy.getPolicy(PolicyType.SINGLE_MLDSA, ScriptType.P2MR, wallet.getKeystores(), 1));
        return wallet;
    }

    @Test
    public void testWalletSignsAndFinalisesCoreShapedPsbt() throws Exception {
        Wallet wallet = buildWallet();
        WalletNode receive0 = new WalletNode(wallet, KeyPurpose.RECEIVE, 0);
        Script nodeScript = wallet.getOutputScript(receive0);

        //Build the PSBT the way Core does: witness UTXO only, no P2MR fields
        byte[] prevHash = new byte[32];
        Arrays.fill(prevHash, (byte)0x22);
        Transaction tx = new Transaction();
        tx.setVersion(2);
        tx.addInput(Sha256Hash.wrap(prevHash), 0, new Script(new byte[0]));
        tx.addOutput(80_000L, nodeScript);

        PSBT psbt = new PSBT(tx);
        PSBTInput input = psbt.getPsbtInputs().get(0);
        input.setWitnessUtxo(new TransactionOutput(tx, 100_000L, nodeScript));
        Assertions.assertNull(input.getP2mrLeafScript(), "precondition: Core supplies no leaf script");

        wallet.sign(psbt);

        //Wallet.sign must have supplied the leaf/root and produced a valid ML-DSA signature
        byte[] pubKey = wallet.getKeystores().get(0).getBtqPublicKey(KeyPurpose.RECEIVE, 0);
        Assertions.assertArrayEquals(P2MR.singleKeyLeafScript(pubKey), input.getP2mrLeafScript());
        Assertions.assertArrayEquals(P2MR.merkleRootForPublicKey(pubKey), input.getP2mrMerkleRoot());
        Assertions.assertTrue(input.isSigned(), "P2MR input must report signed");
        byte[] sighash = BtqPsbtSigner.sighash(psbt, 0);
        Assertions.assertTrue(Mldsa44.verifyTransactionHash(pubKey, sighash, input.getP2mrDilithiumSignature()));

        //Wallet.finalise assembles the witness; the transaction then extracts
        wallet.finalise(psbt);
        Transaction finalTx = psbt.extractTransaction();
        TransactionWitness witness = finalTx.getInputs().get(0).getWitness();
        Assertions.assertEquals(3, witness.getPushCount());
        Assertions.assertArrayEquals(input.getP2mrDilithiumSignature(), witness.getPushes().get(0));
        Assertions.assertArrayEquals(P2MR.singleKeyLeafScript(pubKey), witness.getPushes().get(1));
        Assertions.assertArrayEquals(P2MR.singleLeafControlBlock(), witness.getPushes().get(2));
    }

    @Test
    public void testSignIsIdempotent() throws Exception {
        Wallet wallet = buildWallet();
        WalletNode receive0 = new WalletNode(wallet, KeyPurpose.RECEIVE, 0);
        Script nodeScript = wallet.getOutputScript(receive0);

        byte[] prevHash = new byte[32];
        Arrays.fill(prevHash, (byte)0x33);
        Transaction tx = new Transaction();
        tx.setVersion(2);
        tx.addInput(Sha256Hash.wrap(prevHash), 0, new Script(new byte[0]));
        tx.addOutput(70_000L, nodeScript);

        PSBT psbt = new PSBT(tx);
        psbt.getPsbtInputs().get(0).setWitnessUtxo(new TransactionOutput(tx, 90_000L, nodeScript));

        wallet.sign(psbt);
        byte[] firstSignature = psbt.getPsbtInputs().get(0).getP2mrDilithiumSignature();
        wallet.sign(psbt); //second pass must not re-sign or corrupt
        Assertions.assertArrayEquals(firstSignature, psbt.getPsbtInputs().get(0).getP2mrDilithiumSignature());
    }

    /**
     * The Sparrow UI signs through the signing-nodes overload (HeadersController.signUnencryptedKeystores),
     * not sign(PSBT), and drives its progress/finalize chain from getSignedKeystores - both must work for P2MR.
     */
    @Test
    public void testUiSignPathSignsViaSigningNodesOverload() throws Exception {
        Wallet wallet = buildWallet();
        WalletNode receive0 = new WalletNode(wallet, KeyPurpose.RECEIVE, 0);
        Script nodeScript = wallet.getOutputScript(receive0);

        byte[] prevHash = new byte[32];
        Arrays.fill(prevHash, (byte)0x44);
        Transaction tx = new Transaction();
        tx.setVersion(2);
        tx.addInput(Sha256Hash.wrap(prevHash), 0, new Script(new byte[0]));
        tx.addOutput(60_000L, nodeScript);

        PSBT psbt = new PSBT(tx);
        PSBTInput input = psbt.getPsbtInputs().get(0);
        input.setWitnessUtxo(new TransactionOutput(tx, 80_000L, nodeScript));

        Map<PSBTInput, Map<TransactionSignature, Keystore>> unsigned = wallet.getSignedKeystores(psbt);
        Assertions.assertTrue(unsigned.containsKey(input));
        Assertions.assertTrue(unsigned.get(input).isEmpty(), "unsigned input must report no signatures");

        wallet.sign(wallet.getSigningNodes(psbt));

        Assertions.assertTrue(input.isSigned(), "P2MR input must be signed via the signing-nodes overload");
        byte[] pubKey = wallet.getKeystores().get(0).getBtqPublicKey(KeyPurpose.RECEIVE, 0);
        byte[] sighash = BtqPsbtSigner.sighash(psbt, 0);
        Assertions.assertTrue(Mldsa44.verifyTransactionHash(pubKey, sighash, input.getP2mrDilithiumSignature()));

        Map<PSBTInput, Map<TransactionSignature, Keystore>> signed = wallet.getSignedKeystores(psbt);
        Assertions.assertEquals(1, signed.get(input).size(), "signed input must report its keystore for UI progress");
        Assertions.assertSame(wallet.getKeystores().get(0), signed.get(input).values().iterator().next());
    }
}
