package com.sparrowwallet.drongo.address;

import com.sparrowwallet.drongo.Network;
import com.sparrowwallet.drongo.protocol.Bech32;
import com.sparrowwallet.drongo.protocol.ScriptType;

/**
 * A Bitcoin Quantum Pay-to-Merkle-Root (P2MR) address (BIP360, witness version 2).
 * <p>
 * The address commits to the 32-byte Merkle root of a Dilithium script tree and is encoded as
 * {@code Bech32m(btqHrp, witnessVersion = 2, merkleRoot)} under the network's BTQ HRP
 * ({@code qbtc}/{@code tbtq}/{@code qtb}/{@code qcrt}) - e.g. {@code qbtc1z...} / {@code tbtq1z...}.
 * The address data is the 32-byte witness program (the script-tree Merkle root).
 */
public class P2MRAddress extends Address {
    public P2MRAddress(byte[] merkleRoot) {
        super(merkleRoot);
        if(merkleRoot.length != 32) {
            throw new IllegalArgumentException("P2MR witness program must be exactly 32 bytes, not " + merkleRoot.length);
        }
    }

    @Override
    public int getVersion(Network network) {
        return 2;
    }

    @Override
    public String getAddress(Network network) {
        return Bech32.encode(network.getBtqBech32AddressHRP(), getVersion(network), data);
    }

    @Override
    public ScriptType getScriptType() {
        return ScriptType.P2MR;
    }

    @Override
    public String getOutputScriptDataType() {
        return "Dilithium P2MR";
    }
}
