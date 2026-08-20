package com.sparrowwallet.drongo.btq;

import com.sparrowwallet.drongo.KeyPurpose;
import com.sparrowwallet.drongo.Network;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Objects;

/**
 * The Bitcoin Quantum custody key derivation: one 32-byte master secret derives independent
 * receive/change ML-DSA-44 key seeds through HKDF-SHA512 (RFC 5869, single expand block).
 * <p>
 * Relocated byte-exactly from the Qparrow custody format (v1) proven on BTQ public testnet: the network
 * is deliberately bound into derivation via BTQ Core's RPC chain name ({@code main}/{@code test}/
 * {@code signet}/{@code regtest}), so a development backup cannot silently become a mainnet wallet.
 * There is no public derivation - deriving any key material requires the master secret.
 */
public final class BtqDerivation {
    public static final int MASTER_SECRET_BYTES = 32;
    public static final int MAX_INDEX = 0x7fffffff;

    private static final byte[] HKDF_SALT = "Qparrow/BTQ/Custody/v1".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] KEY_INFO = "ML-DSA-44/P2MR".getBytes(StandardCharsets.US_ASCII);

    private BtqDerivation() {
    }

    public enum Chain {
        RECEIVE(0),
        CHANGE(1);

        private final int id;

        Chain(int id) {
            this.id = id;
        }

        public static Chain fromKeyPurpose(KeyPurpose keyPurpose) {
            return keyPurpose == KeyPurpose.CHANGE ? CHANGE : RECEIVE;
        }
    }

    /** BTQ Core's RPC chain name for a network - the exact string bound into the derivation info. */
    public static String rpcChain(Network network) {
        return switch(network) {
            case MAINNET -> "main";
            case TESTNET, TESTNET4 -> "test";
            case SIGNET -> "signet";
            case REGTEST -> "regtest";
        };
    }

    /** Derive one 32-byte ML-DSA key-generation seed. The caller must zeroize the returned seed after use. */
    public static byte[] deriveKeySeed(byte[] masterSecret, Network network, Chain chain, int index) {
        if(masterSecret == null || masterSecret.length != MASTER_SECRET_BYTES) {
            throw new IllegalArgumentException("master secret must be exactly " + MASTER_SECRET_BYTES + " bytes");
        }
        Objects.requireNonNull(network, "network");
        Objects.requireNonNull(chain, "chain");
        if(index < 0 || index > MAX_INDEX) {
            throw new IllegalArgumentException("derivation index must be between 0 and " + MAX_INDEX);
        }

        byte[] prk = hmacSha512(HKDF_SALT, masterSecret);
        byte[] networkId = rpcChain(network).getBytes(StandardCharsets.US_ASCII);
        ByteBuffer info = ByteBuffer.allocate(KEY_INFO.length + 1 + networkId.length + 1 + Integer.BYTES + 1);
        info.put(KEY_INFO);
        info.put((byte)0);
        info.put(networkId);
        info.put((byte)chain.id);
        info.putInt(index);
        info.put((byte)1); //RFC 5869 first expand block

        byte[] expanded = null;
        try {
            expanded = hmacSha512(prk, info.array());
            return Arrays.copyOf(expanded, Mldsa44.SEED_BYTES);
        } finally {
            Arrays.fill(prk, (byte)0);
            if(expanded != null) {
                Arrays.fill(expanded, (byte)0);
            }
            Arrays.fill(info.array(), (byte)0);
        }
    }

    /** Derive the 1312-byte ML-DSA public key for a chain/index, zeroizing the intermediate key seed. */
    public static byte[] derivePublicKey(byte[] masterSecret, Network network, Chain chain, int index) {
        byte[] keySeed = deriveKeySeed(masterSecret, network, chain, index);
        try {
            return Mldsa44.publicKeyFromSeed(keySeed);
        } finally {
            Arrays.fill(keySeed, (byte)0);
        }
    }

    private static byte[] hmacSha512(byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA512");
            mac.init(new SecretKeySpec(key, "HmacSHA512"));
            return mac.doFinal(data);
        } catch(GeneralSecurityException e) {
            throw new IllegalStateException("HmacSHA512 is unavailable", e);
        }
    }
}
