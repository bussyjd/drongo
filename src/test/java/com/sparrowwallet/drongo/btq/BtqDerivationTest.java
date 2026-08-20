package com.sparrowwallet.drongo.btq;

import com.sparrowwallet.drongo.Network;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.HexFormat;

/**
 * Golden-vector tests for the BTQ custody HKDF-SHA512 derivation. Expected seeds were produced by an
 * independent Python reference of the RFC 5869 extract/expand construction with the Qparrow v1 salt and
 * info layout - byte-compatibility here is what keeps existing custody wallets (including the funded
 * public-testnet wallet) recoverable.
 */
public class BtqDerivationTest {
    private static final HexFormat HEX = HexFormat.of();

    private static byte[] master() {
        byte[] master = new byte[BtqDerivation.MASTER_SECRET_BYTES];
        for(int i = 0; i < master.length; i++) {
            master[i] = (byte)i;
        }
        return master;
    }

    @Test
    public void testGoldenVectors() {
        Assertions.assertEquals("02af08c552c9059305eab6a946134de61c4b73cf34e9d4b6223be98e39d928bf",
                HEX.formatHex(BtqDerivation.deriveKeySeed(master(), Network.TESTNET, BtqDerivation.Chain.RECEIVE, 0)));
        Assertions.assertEquals("518eed000ea7a3d14c5040d1c9cf24def6316b47acd05c0c9cc3e6cbf96b4ce6",
                HEX.formatHex(BtqDerivation.deriveKeySeed(master(), Network.TESTNET, BtqDerivation.Chain.RECEIVE, 5)));
        Assertions.assertEquals("d706b13d864883f36a08dcd93e91d7de3c865b3d7a87797457a7a884bc961672",
                HEX.formatHex(BtqDerivation.deriveKeySeed(master(), Network.TESTNET, BtqDerivation.Chain.CHANGE, 0)));
        Assertions.assertEquals("03d72656440b5dfe73998e43e8b3fe2b463e57a140294e28b6b90cc115ec4b9d",
                HEX.formatHex(BtqDerivation.deriveKeySeed(master(), Network.MAINNET, BtqDerivation.Chain.RECEIVE, 0)));
        Assertions.assertEquals("d99f98a20c8360893ef0687e439de47901558fb887a170a94df9b00d3fd12cfb",
                HEX.formatHex(BtqDerivation.deriveKeySeed(master(), Network.REGTEST, BtqDerivation.Chain.RECEIVE, 0)));
    }

    @Test
    public void testNetworkBinding() {
        //TESTNET4 shares the "test" rpc chain; every other network derives differently
        Assertions.assertArrayEquals(
                BtqDerivation.deriveKeySeed(master(), Network.TESTNET, BtqDerivation.Chain.RECEIVE, 0),
                BtqDerivation.deriveKeySeed(master(), Network.TESTNET4, BtqDerivation.Chain.RECEIVE, 0));
        Assertions.assertFalse(java.util.Arrays.equals(
                BtqDerivation.deriveKeySeed(master(), Network.MAINNET, BtqDerivation.Chain.RECEIVE, 0),
                BtqDerivation.deriveKeySeed(master(), Network.TESTNET, BtqDerivation.Chain.RECEIVE, 0)));
    }

    @Test
    public void testRpcChainNames() {
        Assertions.assertEquals("main", BtqDerivation.rpcChain(Network.MAINNET));
        Assertions.assertEquals("test", BtqDerivation.rpcChain(Network.TESTNET));
        Assertions.assertEquals("signet", BtqDerivation.rpcChain(Network.SIGNET));
        Assertions.assertEquals("regtest", BtqDerivation.rpcChain(Network.REGTEST));
    }

    @Test
    public void testDerivePublicKey() {
        byte[] publicKey = BtqDerivation.derivePublicKey(master(), Network.TESTNET, BtqDerivation.Chain.RECEIVE, 0);
        Assertions.assertEquals(Mldsa44.PUBLIC_KEY_BYTES, publicKey.length);
        //Deterministic
        Assertions.assertArrayEquals(publicKey, BtqDerivation.derivePublicKey(master(), Network.TESTNET, BtqDerivation.Chain.RECEIVE, 0));
    }

    @Test
    public void testRejectsInvalidInputs() {
        Assertions.assertThrows(IllegalArgumentException.class,
                () -> BtqDerivation.deriveKeySeed(new byte[31], Network.TESTNET, BtqDerivation.Chain.RECEIVE, 0));
        Assertions.assertThrows(IllegalArgumentException.class,
                () -> BtqDerivation.deriveKeySeed(master(), Network.TESTNET, BtqDerivation.Chain.RECEIVE, -1));
    }
}
