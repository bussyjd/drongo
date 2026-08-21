package com.sparrowwallet.drongo.wallet;

import com.sparrowwallet.drongo.KeyPurpose;
import com.sparrowwallet.drongo.Network;
import com.sparrowwallet.drongo.address.Address;
import com.sparrowwallet.drongo.btq.Mldsa44;
import com.sparrowwallet.drongo.btq.P2MR;
import com.sparrowwallet.drongo.policy.Policy;
import com.sparrowwallet.drongo.policy.PolicyType;
import com.sparrowwallet.drongo.protocol.Script;
import com.sparrowwallet.drongo.protocol.ScriptType;
import com.sparrowwallet.drongo.protocol.Sha256Hash;
import com.sparrowwallet.drongo.protocol.Transaction;
import com.sparrowwallet.drongo.protocol.TransactionWitness;
import com.sparrowwallet.drongo.psbt.PSBT;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.TreeSet;

/**
 * The full local Send pipeline for a Bitcoin Quantum wallet, exactly as Sparrow's Send tab drives it:
 * a funded wallet model -> createWalletTransaction (coin selection at BTQ's scale-16 weights) ->
 * createPSBT -> Wallet.sign -> Wallet.finalise -> extract. Proves the SendController flow needs no
 * BTQ-specific construction path.
 */
public class BtqWalletSendTest {
    private static byte[] master() {
        byte[] master = new byte[32];
        for(int i = 0; i < master.length; i++) {
            master[i] = (byte)(0x50 + i);
        }
        return master;
    }

    private static Wallet buildFundedWallet() {
        Wallet wallet = new Wallet("BTQ Send Wallet");
        wallet.setPolicyType(PolicyType.SINGLE_MLDSA);
        wallet.setScriptType(ScriptType.P2MR);
        wallet.getKeystores().add(Keystore.fromBtqMasterSecret(master(), Network.get()));
        wallet.setDefaultPolicy(Policy.getPolicy(PolicyType.SINGLE_MLDSA, ScriptType.P2MR, wallet.getKeystores(), 1));
        wallet.setStoredBlockHeight(200);

        //Fund receive-0 with a 1,000,000 sat coinbase-like transaction recorded in the wallet model
        wallet.getNode(KeyPurpose.RECEIVE).fillToIndex(wallet, 0);
        wallet.getNode(KeyPurpose.CHANGE).fillToIndex(wallet, 0);
        WalletNode receive0 = wallet.getNode(KeyPurpose.RECEIVE).getChildren().stream()
                .filter(node -> node.getIndex() == 0).findFirst().orElseThrow();
        Script nodeScript = wallet.getOutputScript(receive0);

        byte[] prevHash = new byte[32];
        java.util.Arrays.fill(prevHash, (byte)0x44);
        Transaction fundingTx = new Transaction();
        fundingTx.setVersion(2);
        fundingTx.addInput(Sha256Hash.wrap(prevHash), 0, new Script(new byte[0]));
        fundingTx.addOutput(1_000_000L, nodeScript);

        BlockTransaction fundingBlockTx = new BlockTransaction(fundingTx.getTxId(), 100, new Date(1_700_000_000_000L), 0L, fundingTx);
        wallet.updateTransactions(java.util.Map.of(fundingTx.getTxId(), fundingBlockTx));

        TreeSet<BlockTransactionHashIndex> txos = new TreeSet<>();
        txos.add(new BlockTransactionHashIndex(fundingTx.getTxId(), 100, fundingBlockTx.getDate(), 0L, 0, 1_000_000L));
        receive0.updateTransactionOutputs(wallet, txos);
        return wallet;
    }

    @Test
    public void testFullSendPipeline() throws Exception {
        Wallet wallet = buildFundedWallet();
        byte[] destinationKey = Mldsa44.publicKeyFromSeed(new byte[32]);
        Address destination = P2MR.addressForPublicKey(destinationKey);

        TransactionParameters params = new TransactionParameters(
                List.of(new PresetUtxoSelector(wallet.getWalletUtxos().keySet())), List.of(),
                List.of(new Payment(destination, "test payment", 200_000L, false)),
                List.of(), Collections.emptySet(), 2.0d, 2.0d, 1.0d, null, 200, false, false, true);

        WalletTransaction walletTransaction = wallet.createWalletTransaction(params);
        Assertions.assertFalse(walletTransaction.getSelectedUtxos().isEmpty());

        //The fee must reflect BTQ's scale-16 economics: ~276 vB input + outputs/overhead, NOT scale-4 (~1101 vB input)
        long fee = walletTransaction.getFee();
        Assertions.assertTrue(fee > 0 && fee < 2_000L,
                "fee should be a few hundred sats at 2 sat/vB with a 276 vB input, was " + fee);

        PSBT psbt = walletTransaction.createPSBT();
        Assertions.assertNotNull(psbt.getPsbtInputs().get(0).getWitnessUtxo(), "P2MR input must carry its witness UTXO");

        wallet.sign(psbt);
        Assertions.assertTrue(psbt.getPsbtInputs().get(0).isSigned());

        wallet.finalise(psbt);
        Transaction finalTx = psbt.extractTransaction();
        TransactionWitness witness = finalTx.getInputs().get(0).getWitness();
        Assertions.assertEquals(3, witness.getPushCount());
        Assertions.assertEquals(Mldsa44.TRANSACTION_SIGNATURE_BYTES, witness.getPushes().get(0).length);

        //The payment output and a change output both exist and are P2MR
        Assertions.assertEquals(2, finalTx.getOutputs().size());
        for(var output : finalTx.getOutputs()) {
            Assertions.assertEquals(ScriptType.P2MR, ScriptType.getType(output.getScript()));
        }
    }
}
