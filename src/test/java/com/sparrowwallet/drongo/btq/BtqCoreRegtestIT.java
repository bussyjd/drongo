package com.sparrowwallet.drongo.btq;

import com.sparrowwallet.drongo.Network;
import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.protocol.Transaction;
import com.sparrowwallet.drongo.psbt.PSBT;
import com.sparrowwallet.drongo.psbt.PSBTInput;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Live cross-check that {@link BtqPsbtSigner} produces a P2MR spend that BTQ Core accepts on regtest.
 * <p>
 * Drives a private regtest btqd (fresh datadir, unique ports - never the user's running node) through
 * btq-cli: funds a single-leaf ML-DSA P2MR address derived in the JVM, has Core build a funded PSBT for
 * it, signs and finalizes with {@link BtqPsbtSigner}, then asserts {@code testmempoolaccept} allows the
 * transaction and that it confirms. Skips cleanly when {@code BTQ_CORE_BIN} is unset.
 */
class BtqCoreRegtestIT {
    @TempDir
    Path temporaryDirectory;

    private Path binary;
    private Path dataDirectory;
    private int rpcPort;

    @Test
    void btqPsbtSignerTransactionIsAcceptedByBtqCore() throws Exception {
        String binarySetting = System.getenv("BTQ_CORE_BIN");
        assumeTrue(binarySetting != null && !binarySetting.isBlank(),
                "Set BTQ_CORE_BIN to run the live BTQ Core regtest cross-check");
        binary = Path.of(binarySetting).toAbsolutePath();
        assumeTrue(Files.isExecutable(binary), "BTQ_CORE_BIN is not executable: " + binary);
        Path cli = binary.resolveSibling("btq-cli");
        assumeTrue(Files.isExecutable(cli), "btq-cli not found next to BTQ_CORE_BIN: " + cli);

        dataDirectory = temporaryDirectory.resolve("node");
        Files.createDirectories(dataDirectory);
        rpcPort = freePort();
        int p2pPort = freePort();
        Path log = temporaryDirectory.resolve("btqd.log");
        ProcessBuilder nodeBuilder = new ProcessBuilder(binary.toString(), "-regtest", "-datadir=" + dataDirectory,
                "-server=1", "-rpcbind=127.0.0.1", "-rpcallowip=127.0.0.1", "-rpcport=" + rpcPort,
                "-port=" + p2pPort, "-listen=0", "-dnsseed=0", "-discover=0", "-fallbackfee=0.00001", "-txindex=1",
                "-printtoconsole=1")
                .redirectErrorStream(true).redirectOutput(ProcessBuilder.Redirect.appendTo(log.toFile()));
        Process process = nodeBuilder.start();

        try {
            waitForNode(process, log);

            // 2. Mining wallet with a matured coinbase balance.
            rpc("createwallet", "miner");
            String miningAddress = walletRpc("miner", "getnewaddress", "mining", "bech32").trim();
            walletRpc("miner", "generatetoaddress", "101", miningAddress);

            // 3. Derive a single-leaf P2MR address entirely in the JVM.
            byte[] seed = new byte[Mldsa44.SEED_BYTES];
            for(int i = 0; i < seed.length; i++) {
                seed[i] = (byte)(i + 1);
            }
            byte[] publicKey = Mldsa44.publicKeyFromSeed(seed);
            P2MR.P2MRScript p2mr = P2MR.scriptForPublicKey(Network.REGTEST, publicKey);
            String p2mrAddress = p2mr.address();
            assertTrue(p2mrAddress.startsWith("qcrt1z"), "expected a regtest P2MR address, got " + p2mrAddress);

            // 4. Watch-only wallet importing the P2MR address by descriptor.
            rpc("createwallet", "watch", "true", "true");
            String descInfo = walletRpc("watch", "getdescriptorinfo", "addr(" + p2mrAddress + ")");
            String descriptor = extractString(descInfo, "descriptor");
            assertNotNull(descriptor, "getdescriptorinfo returned no descriptor: " + descInfo);
            String importRequest = "[{\"desc\":\"" + descriptor + "\",\"timestamp\":\"now\"}]";
            String importResult = walletRpc("watch", "importdescriptors", importRequest);
            assertTrue(extractBool(importResult, "success"), "importdescriptors failed: " + importResult);

            // 5. Fund the P2MR address from the miner and confirm it.
            String fundingTxid = walletRpc("miner", "sendtoaddress", p2mrAddress, "1.0").trim();
            assertEquals(64, fundingTxid.length(), "unexpected funding txid: " + fundingTxid);
            walletRpc("miner", "generatetoaddress", "1", miningAddress);

            // 6. Locate the P2MR UTXO from the watch wallet.
            String unspent = walletRpc("watch", "listunspent", "1", "9999999",
                    "[\"" + p2mrAddress + "\"]");
            String utxoTxid = extractString(unspent, "txid");
            assertNotNull(utxoTxid, "no P2MR UTXO found in listunspent: " + unspent);
            long vout = extractLong(unspent, "vout");

            // 6b. Have Core build a funded PSBT spending only that P2MR input, paying back to the
            //     same address; the witness weight hint (input ~4402 WU) lets Core size the fee.
            String inputs = "[{\"txid\":\"" + utxoTxid + "\",\"vout\":" + vout + ",\"weight\":4402}]";
            String outputs = "[{\"" + p2mrAddress + "\":1.0}]";
            String options = "{\"subtractFeeFromOutputs\":[0],\"add_inputs\":false}";
            String funded = walletRpc("watch", "walletcreatefundedpsbt", inputs, outputs, "0", options);
            String base64Psbt = extractString(funded, "psbt");
            assertNotNull(base64Psbt, "walletcreatefundedpsbt returned no psbt: " + funded);
            long coreFeeSats = new java.math.BigDecimal(extractRaw(funded, "fee"))
                    .movePointRight(8).longValueExact();

            // 7. Parse the Core PSBT with drongo and record whether Core populated the P2MR fields.
            PSBT psbt = new PSBT(Base64.getDecoder().decode(base64Psbt), false);
            int p2mrInputIndex = findP2mrInput(psbt, p2mr.outputScript());
            assertTrue(p2mrInputIndex >= 0, "no input matched the P2MR output script");
            assertEquals(1, psbt.getPsbtInputs().size(), "test requires a single P2MR input");
            PSBTInput input = psbt.getPsbtInputs().get(p2mrInputIndex);
            assertNotNull(input.getWitnessUtxo(), "Core PSBT input is missing its witness UTXO");

            boolean coreSuppliedLeaf = input.getP2mrLeafScript() != null;
            boolean coreSuppliedRoot = input.getP2mrMerkleRoot() != null;
            if(!coreSuppliedLeaf) {
                input.setP2mrLeaf(p2mr.leafScript(), (byte)P2MR.LEAF_VERSION, p2mr.controlBlock());
            }
            if(!coreSuppliedRoot) {
                input.setP2mrMerkleRoot(p2mr.merkleRoot());
            }

            // 8-9. Sign, finalize, serialize.
            BtqPsbtSigner.sign(psbt, Map.of(p2mrInputIndex, seed));
            long drongoFeeSats = BtqPsbtSigner.feeSats(psbt);
            Transaction tx = BtqPsbtSigner.finalise(psbt);
            String txHex = Utils.bytesToHex(tx.bitcoinSerialize());

            // 10. THE assertion: BTQ Core must accept the drongo-built transaction.
            String acceptance = rpc("testmempoolaccept", "[\"" + txHex + "\"]");
            boolean allowed = extractBool(acceptance, "allowed");
            assertTrue(allowed, "BTQ Core rejected the BtqPsbtSigner transaction: " + acceptance);

            String broadcastTxid = rpc("sendrawtransaction", txHex).trim();
            assertEquals(tx.getTxId().toString(), broadcastTxid, "broadcast txid mismatch");
            walletRpc("miner", "generatetoaddress", "1", miningAddress);
            String confirmed = rpc("getrawtransaction", broadcastTxid, "true");
            long confirmations = extractLong(confirmed, "confirmations");
            assertTrue(confirmations >= 1, "transaction not confirmed: " + confirmed);

            System.out.println("[BtqCoreRegtestIT] PASS txid=" + broadcastTxid
                    + " coreFeeSats=" + coreFeeSats + " drongoFeeSats=" + drongoFeeSats
                    + " confirmations=" + confirmations
                    + " coreSuppliedLeaf(0x19)=" + coreSuppliedLeaf
                    + " coreSuppliedRoot(0x1a)=" + coreSuppliedRoot);
        } finally {
            if(process.isAlive()) {
                try {
                    rpc("stop");
                } catch(Exception ignored) {
                    process.destroy();
                }
                if(!process.waitFor(10, TimeUnit.SECONDS)) {
                    process.destroyForcibly();
                    process.waitFor(5, TimeUnit.SECONDS);
                }
            }
        }
    }

    /** Find the input whose witness UTXO scriptPubKey equals the derived P2MR output script. */
    private static int findP2mrInput(PSBT psbt, byte[] outputScript) {
        List<PSBTInput> inputs = psbt.getPsbtInputs();
        for(int i = 0; i < inputs.size(); i++) {
            var witnessUtxo = inputs.get(i).getWitnessUtxo();
            if(witnessUtxo != null && Arrays.equals(witnessUtxo.getScript().getProgram(), outputScript)) {
                return i;
            }
        }
        return -1;
    }

    private String rpc(String... method) throws Exception {
        return cli(null, method);
    }

    private String walletRpc(String wallet, String... method) throws Exception {
        return cli(wallet, method);
    }

    private String cli(String wallet, String[] method) throws Exception {
        List<String> command = new ArrayList<>();
        command.add(binary.resolveSibling("btq-cli").toString());
        command.add("-regtest");
        command.add("-datadir=" + dataDirectory);
        command.add("-rpcport=" + rpcPort);
        if(wallet != null) {
            command.add("-rpcwallet=" + wallet);
        }
        command.addAll(Arrays.asList(method));
        ProcessBuilder builder = new ProcessBuilder(command);
        Process cliProcess = builder.start();
        byte[] out = cliProcess.getInputStream().readAllBytes();
        byte[] err = cliProcess.getErrorStream().readAllBytes();
        if(!cliProcess.waitFor(60, TimeUnit.SECONDS)) {
            cliProcess.destroyForcibly();
            throw new IllegalStateException("btq-cli timed out: " + Arrays.toString(method));
        }
        String stdout = new String(out, StandardCharsets.UTF_8);
        if(cliProcess.exitValue() != 0) {
            throw new IllegalStateException("btq-cli " + method[0] + " failed (exit "
                    + cliProcess.exitValue() + "): " + new String(err, StandardCharsets.UTF_8) + stdout);
        }
        return stdout;
    }

    private void waitForNode(Process process, Path log) throws Exception {
        Path cookie = dataDirectory.resolve("regtest").resolve(".cookie");
        Instant deadline = Instant.now().plusSeconds(45);
        Exception lastError = null;
        while(Instant.now().isBefore(deadline)) {
            if(!process.isAlive()) {
                fail("BTQ Core exited during startup. Log:\n" + Files.readString(log));
            }
            if(Files.isRegularFile(cookie)) {
                try {
                    rpc("getblockchaininfo");
                    return;
                } catch(Exception e) {
                    lastError = e;
                }
            }
            Thread.sleep(150);
        }
        fail("BTQ Core did not become ready: " + (lastError == null ? "no RPC response" : lastError.getMessage())
                + "\nLog:\n" + Files.readString(log));
    }

    private static int freePort() throws Exception {
        try(ServerSocket socket = new ServerSocket(0)) {
            socket.setReuseAddress(true);
            return socket.getLocalPort();
        }
    }

    private static String extractString(String json, String key) {
        Matcher m = Pattern.compile("\"" + Pattern.quote(key) + "\"\\s*:\\s*\"([^\"]*)\"").matcher(json);
        return m.find() ? m.group(1) : null;
    }

    private static String extractRaw(String json, String key) {
        Matcher m = Pattern.compile("\"" + Pattern.quote(key) + "\"\\s*:\\s*(-?[0-9.]+)").matcher(json);
        if(!m.find()) {
            throw new IllegalStateException("no numeric field '" + key + "' in: " + json);
        }
        return m.group(1);
    }

    private static long extractLong(String json, String key) {
        return Long.parseLong(extractRaw(json, key).split("\\.")[0]);
    }

    private static boolean extractBool(String json, String key) {
        Matcher m = Pattern.compile("\"" + Pattern.quote(key) + "\"\\s*:\\s*(true|false)").matcher(json);
        return m.find() && Boolean.parseBoolean(m.group(1));
    }
}
