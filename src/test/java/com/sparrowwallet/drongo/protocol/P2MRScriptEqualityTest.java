package com.sparrowwallet.drongo.protocol;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import java.util.HexFormat;

/** Reproduces the funds-matching failure: a parsed P2MR output script vs a constructed one. */
public class P2MRScriptEqualityTest {
    @Test
    public void testParsedEqualsConstructed() {
        byte[] root = HexFormat.of().parseHex("f890d4ab741fe53b56f874b36111373abebc9af26f2a03ff55f682aa2feb5925");
        byte[] spkBytes = HexFormat.of().parseHex("5220f890d4ab741fe53b56f874b36111373abebc9af26f2a03ff55f682aa2feb5925");

        Script parsed = new Script(spkBytes);                       // from a transaction output
        Script constructed = ScriptType.P2MR.getOutputScript(root); // from a wallet node

        System.err.println("[TEST] parsed.getProgram=" + HexFormat.of().formatHex(parsed.getProgram()));
        System.err.println("[TEST] constructed.getProgram=" + HexFormat.of().formatHex(constructed.getProgram()));
        System.err.println("[TEST] parsed.class=" + parsed.getClass() + " constructed.class=" + constructed.getClass());
        System.err.println("[TEST] parsed.equals(constructed)=" + parsed.equals(constructed));
        System.err.println("[TEST] constructed.equals(parsed)=" + constructed.equals(parsed));

        Assertions.assertArrayEquals(parsed.getProgram(), constructed.getProgram());
        Assertions.assertEquals(parsed, constructed);
        Assertions.assertEquals(constructed, parsed);
    }
}
