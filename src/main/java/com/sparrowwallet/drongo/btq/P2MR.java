package com.sparrowwallet.drongo.btq;

import com.sparrowwallet.drongo.Network;
import com.sparrowwallet.drongo.address.P2MRAddress;

import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Objects;

import static com.sparrowwallet.drongo.protocol.ScriptOpCodes.OP_2;
import static com.sparrowwallet.drongo.protocol.ScriptOpCodes.OP_CHECKSIGDILITHIUM;
import static com.sparrowwallet.drongo.protocol.ScriptOpCodes.OP_PUSHDATA2;

/**
 * Bitcoin Quantum Pay-to-Merkle-Root (P2MR, BIP360) single-leaf construction.
 * <p>
 * A P2MR output commits to the 32-byte TapLeaf-tagged Merkle root of a script tree. The custody wallet
 * uses exactly one leaf holding one ML-DSA-44 key:
 * <pre>{@code OP_PUSHDATA2 <1312-byte pubkey> OP_CHECKSIGDILITHIUM}</pre>
 * with leaf version {@value #LEAF_VERSION}. For a single leaf the Merkle root equals the leaf's TapLeaf
 * hash, and the output script is {@code OP_2 <32-byte root>}. Relocated from the Qparrow reference
 * implementation, which was validated against BTQ Core on public testnet.
 */
public final class P2MR {
    public static final int LEAF_VERSION = 0xc0;
    public static final int CONTROL_BYTE = 0xc1;
    /** Each Merkle path node in a P2MR control block, after its single control byte. */
    public static final int CONTROL_NODE_BYTES = 32;
    /** The deepest script tree a P2MR control block may prove membership in (BTQ Core's P2MR_CONTROL_MAX_NODE_COUNT). */
    public static final int CONTROL_MAX_NODE_COUNT = 128;

    private static final byte[] TAP_LEAF_TAG = sha256("TapLeaf".getBytes(java.nio.charset.StandardCharsets.US_ASCII));
    private static final byte[] TAP_BRANCH_TAG = sha256("TapBranch".getBytes(java.nio.charset.StandardCharsets.US_ASCII));

    private P2MR() {
    }

    /** The single-key leaf script: {@code OP_PUSHDATA2 <1312-byte pubkey> OP_CHECKSIGDILITHIUM}. */
    public static byte[] singleKeyLeafScript(byte[] publicKey) {
        Mldsa44.requireLength(publicKey, Mldsa44.PUBLIC_KEY_BYTES, "ML-DSA public key");
        ByteArrayOutputStream script = new ByteArrayOutputStream(Mldsa44.PUBLIC_KEY_BYTES + 4);
        script.write(OP_PUSHDATA2);
        script.write(Mldsa44.PUBLIC_KEY_BYTES & 0xff);
        script.write((Mldsa44.PUBLIC_KEY_BYTES >>> 8) & 0xff);
        script.writeBytes(publicKey);
        script.write(OP_CHECKSIGDILITHIUM);
        return script.toByteArray();
    }

    /**
     * The ML-DSA public key of a canonical single-key leaf script, or null when the script is anything else.
     * Only the exact {@link #singleKeyLeafScript} encoding is accepted, so a non-canonical push of the same key yields null.
     */
    public static byte[] publicKeyFromSingleKeyLeafScript(byte[] leafScript) {
        if(leafScript == null || leafScript.length != Mldsa44.PUBLIC_KEY_BYTES + 4) {
            return null;
        }
        byte[] publicKey = Arrays.copyOfRange(leafScript, 3, 3 + Mldsa44.PUBLIC_KEY_BYTES);
        return Arrays.equals(singleKeyLeafScript(publicKey), leafScript) ? publicKey : null;
    }

    /** The BIP341 TapLeaf hash {@code tagged_hash("TapLeaf", leafVersion || compactSize(len) || script)}. */
    public static byte[] tapLeafHash(byte[] leafScript) {
        Objects.requireNonNull(leafScript, "leafScript");
        ByteArrayOutputStream encoded = new ByteArrayOutputStream(leafScript.length + 4);
        encoded.write(LEAF_VERSION);
        writeCompactSize(encoded, leafScript.length);
        encoded.writeBytes(leafScript);

        MessageDigest digest = sha256Digest();
        digest.update(TAP_LEAF_TAG);
        digest.update(TAP_LEAF_TAG);
        return digest.digest(encoded.toByteArray());
    }

    /** The 32-byte P2MR witness program (single-leaf Merkle root) for a single ML-DSA key. */
    public static byte[] merkleRootForPublicKey(byte[] publicKey) {
        return tapLeafHash(singleKeyLeafScript(publicKey));
    }

    /** The output script {@code OP_2 <32-byte root>} (34 bytes) committing to the given Merkle root. */
    public static byte[] outputScript(byte[] merkleRoot) {
        if(merkleRoot == null || merkleRoot.length != 32) {
            throw new IllegalArgumentException("P2MR Merkle root must be exactly 32 bytes");
        }
        byte[] scriptPubKey = new byte[34];
        scriptPubKey[0] = (byte)OP_2;
        scriptPubKey[1] = 0x20; //push 32 bytes
        System.arraycopy(merkleRoot, 0, scriptPubKey, 2, merkleRoot.length);
        return scriptPubKey;
    }

    /** The single-byte control block ({@value #CONTROL_BYTE}) for the one-leaf tree. */
    public static byte[] singleLeafControlBlock() {
        return new byte[]{(byte)CONTROL_BYTE};
    }

    /**
     * The Merkle root a control block proves the given {@value #LEAF_VERSION} leaf to be part of, folding each path node in
     * with BIP341's sorted TapBranch hash as BTQ Core's {@code ComputeP2MRMerkleRoot} does. For a P2MR output this root is
     * the witness program itself, since P2MR has no internal key to tweak.
     *
     * @return the 32-byte root, or null if the control block is malformed or is not for a {@value #LEAF_VERSION} leaf with
     *         the parity bit BIP360 requires
     */
    public static byte[] merkleRootFromControlBlock(byte[] leafScript, byte[] controlBlock) {
        if(leafScript == null || controlBlock == null || controlBlock.length < 1
                || controlBlock.length > 1 + CONTROL_NODE_BYTES * CONTROL_MAX_NODE_COUNT || (controlBlock.length - 1) % CONTROL_NODE_BYTES != 0) {
            return null;
        }
        if((controlBlock[0] & 0xff) != CONTROL_BYTE) {
            return null;
        }

        byte[] node = tapLeafHash(leafScript);
        for(int offset = 1; offset < controlBlock.length; offset += CONTROL_NODE_BYTES) {
            node = tapBranchHash(node, Arrays.copyOfRange(controlBlock, offset, offset + CONTROL_NODE_BYTES));
        }
        return node;
    }

    /** The BIP341 TapBranch hash {@code tagged_hash("TapBranch", min(a, b) || max(a, b))}. */
    public static byte[] tapBranchHash(byte[] a, byte[] b) {
        boolean ordered = Arrays.compareUnsigned(a, b) <= 0;
        MessageDigest digest = sha256Digest();
        digest.update(TAP_BRANCH_TAG);
        digest.update(TAP_BRANCH_TAG);
        digest.update(ordered ? a : b);
        digest.update(ordered ? b : a);
        return digest.digest();
    }

    public static P2MRAddress addressFromMerkleRoot(byte[] merkleRoot) {
        return new P2MRAddress(merkleRoot);
    }

    public static P2MRAddress addressForPublicKey(byte[] publicKey) {
        return new P2MRAddress(merkleRootForPublicKey(publicKey));
    }

    /** Build the full single-key P2MR script bundle for a given ML-DSA public key. */
    public static P2MRScript scriptForPublicKey(Network network, byte[] publicKey) {
        Objects.requireNonNull(network, "network");
        byte[] leafScript = singleKeyLeafScript(publicKey);
        byte[] merkleRoot = tapLeafHash(leafScript);
        return new P2MRScript(publicKey.clone(), leafScript, merkleRoot, singleLeafControlBlock(),
                outputScript(merkleRoot), new P2MRAddress(merkleRoot).getAddress(network));
    }

    private static void writeCompactSize(ByteArrayOutputStream output, long value) {
        if(value < 0) {
            throw new IllegalArgumentException("negative compact size");
        }
        if(value < 253) {
            output.write((int)value);
        } else if(value <= 0xffffL) {
            output.write(253);
            output.write((int)(value & 0xff));
            output.write((int)((value >>> 8) & 0xff));
        } else {
            throw new IllegalArgumentException("P2MR leaf is unexpectedly large");
        }
    }

    private static byte[] sha256(byte[] input) {
        return sha256Digest().digest(input);
    }

    private static MessageDigest sha256Digest() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch(NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is unavailable", e);
        }
    }

    /** An immutable single-key P2MR script bundle: public key, leaf, Merkle root, control block, output script and address. */
    public record P2MRScript(byte[] publicKey, byte[] leafScript, byte[] merkleRoot, byte[] controlBlock,
                             byte[] outputScript, String address) {
    }
}
