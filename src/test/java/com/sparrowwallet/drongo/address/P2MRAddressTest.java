package com.sparrowwallet.drongo.address;

import com.sparrowwallet.drongo.Network;
import com.sparrowwallet.drongo.protocol.ScriptType;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.HexFormat;

/** Round-trip and cross-network tests for BTQ P2MR (Dilithium, witness v2) address encoding/decoding. */
public class P2MRAddressTest {
    private static final HexFormat HEX = HexFormat.of();
    private static final String MERKLE_ROOT_HEX = "24bb54c16f5d635ca0c844da9817aeb44aab1e661f4167f6cfb5e6116bddb248";
    private static final String ADDR_TESTNET = "tbtq1zyja4fst0t434egxggndfs9awk392k8nxraqk0ak0khnpz67akfyqz23n49";
    private static final String ADDR_MAINNET = "qbtc1zyja4fst0t434egxggndfs9awk392k8nxraqk0ak0khnpz67akfyq8l6m0t";

    @Test
    public void testEncodeVersionAndType() {
        P2MRAddress address = new P2MRAddress(HEX.parseHex(MERKLE_ROOT_HEX));
        Assertions.assertEquals(2, address.getVersion(Network.TESTNET));
        Assertions.assertEquals(ScriptType.P2MR, address.getScriptType());
        Assertions.assertEquals(ADDR_TESTNET, address.getAddress(Network.TESTNET));
        Assertions.assertEquals(ADDR_MAINNET, address.getAddress(Network.MAINNET));
    }

    @Test
    public void testRejectsWrongProgramLength() {
        Assertions.assertThrows(IllegalArgumentException.class, () -> new P2MRAddress(new byte[31]));
        Assertions.assertThrows(IllegalArgumentException.class, () -> new P2MRAddress(new byte[33]));
    }

    @Test
    public void testFromStringRoundTripTestnet() throws InvalidAddressException {
        Address address = Address.fromString(Network.TESTNET, ADDR_TESTNET);
        Assertions.assertInstanceOf(P2MRAddress.class, address);
        Assertions.assertEquals(MERKLE_ROOT_HEX, HEX.formatHex(address.getData()));
        Assertions.assertEquals(ADDR_TESTNET, address.getAddress(Network.TESTNET));
        Assertions.assertEquals(ScriptType.P2MR, address.getScriptType());
    }

    @Test
    public void testFromStringRoundTripMainnet() throws InvalidAddressException {
        Address address = Address.fromString(Network.MAINNET, ADDR_MAINNET);
        Assertions.assertInstanceOf(P2MRAddress.class, address);
        Assertions.assertEquals(MERKLE_ROOT_HEX, HEX.formatHex(address.getData()));
    }

    @Test
    public void testWrongNetworkRejected() {
        //A testnet (tbtq) address must not parse under the mainnet (qbtc) BTQ HRP
        Assertions.assertThrows(InvalidAddressException.class, () -> Address.fromString(Network.MAINNET, ADDR_TESTNET));
    }

    @Test
    public void testBitcoinAddressStillParses() throws InvalidAddressException {
        //Regression guard: the BTQ branch must not disturb Bitcoin native segwit parsing
        Address bitcoin = Address.fromString(Network.MAINNET, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
        Assertions.assertInstanceOf(P2WPKHAddress.class, bitcoin);
    }

    @Test
    public void testTamperedAddressRejected() {
        String tampered = ADDR_TESTNET.substring(0, ADDR_TESTNET.length() - 1) + (ADDR_TESTNET.endsWith("9") ? "8" : "9");
        Assertions.assertThrows(InvalidAddressException.class, () -> Address.fromString(Network.TESTNET, tampered));
    }
}
