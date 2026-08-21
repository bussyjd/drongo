package com.sparrowwallet.drongo.btq;

import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.params.ParametersWithContext;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSASigner;

/**
 * The exact FIPS 204 ML-DSA-44 (Dilithium2) boundary used by Bitcoin Quantum transaction signing.
 * <p>
 * Relocated verbatim from the Qparrow reference implementation, which was validated against BTQ Core
 * on public testnet. Keys and signatures are raw bytes at fixed FIPS 204 sizes; this scheme has no
 * public derivation - a public key can only be produced from the 32-byte seed.
 */
public final class Mldsa44 {
    public static final int SEED_BYTES = 32;
    public static final int PUBLIC_KEY_BYTES = 1312;
    public static final int SECRET_KEY_BYTES = 2560;
    public static final int SIGNATURE_BYTES = 2420;
    public static final int TRANSACTION_SIGNATURE_BYTES = SIGNATURE_BYTES + 1;
    public static final int TRANSACTION_HASH_BYTES = 32;
    public static final byte SIGHASH_ALL = 0x01;

    private static final byte[] EMPTY_CONTEXT = new byte[0];

    private Mldsa44() {
    }

    public static byte[] publicKeyFromSeed(byte[] seed) {
        requireLength(seed, SEED_BYTES, "ML-DSA seed");
        byte[] publicKey = privateKeyFromSeed(seed).getPublicKey();
        requireLength(publicKey, PUBLIC_KEY_BYTES, "ML-DSA public key");
        return publicKey;
    }

    /** Sign the exact 32-byte BTQ transaction sighash with an empty FIPS 204 context, appending the sighash byte. */
    public static byte[] signTransactionHash(byte[] seed, byte[] transactionHash) {
        requireLength(transactionHash, TRANSACTION_HASH_BYTES, "transaction hash");
        byte[] raw = sign(seed, transactionHash, EMPTY_CONTEXT);
        byte[] transactionSignature = new byte[TRANSACTION_SIGNATURE_BYTES];
        System.arraycopy(raw, 0, transactionSignature, 0, raw.length);
        transactionSignature[raw.length] = SIGHASH_ALL;
        return transactionSignature;
    }

    public static boolean verifyTransactionHash(byte[] publicKey, byte[] transactionHash, byte[] transactionSignature) {
        requireLength(publicKey, PUBLIC_KEY_BYTES, "ML-DSA public key");
        requireLength(transactionHash, TRANSACTION_HASH_BYTES, "transaction hash");
        requireLength(transactionSignature, TRANSACTION_SIGNATURE_BYTES, "transaction signature");
        if(transactionSignature[SIGNATURE_BYTES] != SIGHASH_ALL) {
            return false;
        }
        byte[] raw = new byte[SIGNATURE_BYTES];
        System.arraycopy(transactionSignature, 0, raw, 0, raw.length);
        return verify(publicKey, transactionHash, EMPTY_CONTEXT, raw);
    }

    static byte[] sign(byte[] seedOrExpandedKey, byte[] message, byte[] context) {
        if(seedOrExpandedKey == null || (seedOrExpandedKey.length != SEED_BYTES && seedOrExpandedKey.length != SECRET_KEY_BYTES)) {
            throw new IllegalArgumentException("ML-DSA private input must be a 32-byte seed or 2560-byte expanded key");
        }
        if(message == null) {
            throw new IllegalArgumentException("message is required");
        }
        if(context == null || context.length > 255) {
            throw new IllegalArgumentException("ML-DSA context must contain at most 255 bytes");
        }

        MLDSASigner signer = new MLDSASigner();
        signer.init(true, new ParametersWithContext(
                new MLDSAPrivateKeyParameters(MLDSAParameters.ml_dsa_44, seedOrExpandedKey), context));
        signer.update(message, 0, message.length);
        try {
            byte[] signature = signer.generateSignature();
            requireLength(signature, SIGNATURE_BYTES, "ML-DSA signature");
            return signature;
        } catch(CryptoException e) {
            throw new IllegalStateException("ML-DSA signing failed", e);
        }
    }

    static boolean verify(byte[] publicKey, byte[] message, byte[] context, byte[] signature) {
        requireLength(publicKey, PUBLIC_KEY_BYTES, "ML-DSA public key");
        if(message == null) {
            throw new IllegalArgumentException("message is required");
        }
        if(context == null || context.length > 255) {
            throw new IllegalArgumentException("ML-DSA context must contain at most 255 bytes");
        }
        if(signature == null || signature.length != SIGNATURE_BYTES) {
            return false;
        }

        MLDSASigner verifier = new MLDSASigner();
        verifier.init(false, new ParametersWithContext(
                new MLDSAPublicKeyParameters(MLDSAParameters.ml_dsa_44, publicKey), context));
        verifier.update(message, 0, message.length);
        return verifier.verifySignature(signature);
    }

    private static MLDSAPrivateKeyParameters privateKeyFromSeed(byte[] seed) {
        return new MLDSAPrivateKeyParameters(MLDSAParameters.ml_dsa_44, seed);
    }

    static void requireLength(byte[] value, int expected, String label) {
        if(value == null || value.length != expected) {
            throw new IllegalArgumentException(label + " must be exactly " + expected + " bytes");
        }
    }
}
