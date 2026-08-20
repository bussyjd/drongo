package com.sparrowwallet.drongo.wallet;

import com.sparrowwallet.drongo.btq.BtqDerivation;
import com.sparrowwallet.drongo.crypto.EncryptableItem;
import com.sparrowwallet.drongo.crypto.EncryptedData;
import com.sparrowwallet.drongo.crypto.EncryptionType;
import com.sparrowwallet.drongo.crypto.Key;
import com.sparrowwallet.drongo.crypto.KeyCrypter;
import com.sparrowwallet.drongo.crypto.KeyDeriver;

import java.util.Arrays;

/**
 * The 32-byte Bitcoin Quantum custody master secret, encrypted through drongo's standard
 * {@link EncryptableItem} lifecycle (Argon2 key derivation, AES encryption) like
 * {@link MasterPrivateExtendedKey}. All ML-DSA key seeds derive from this secret via
 * {@link BtqDerivation}; there is no mnemonic and no public derivation.
 */
public class BtqMasterSecret extends Persistable implements EncryptableItem {
    private final byte[] secret;

    private final EncryptedData encryptedSecret;

    public BtqMasterSecret(byte[] secret) {
        if(secret == null || secret.length != BtqDerivation.MASTER_SECRET_BYTES) {
            throw new IllegalArgumentException("BTQ master secret must be exactly " + BtqDerivation.MASTER_SECRET_BYTES + " bytes");
        }
        this.secret = secret;
        this.encryptedSecret = null;
    }

    public BtqMasterSecret(EncryptedData encryptedSecret) {
        this.secret = null;
        this.encryptedSecret = encryptedSecret;
    }

    public byte[] getSecret() {
        if(secret == null) {
            throw new IllegalStateException("Cannot get secret bytes for null or encrypted BTQ master secret");
        }
        return secret;
    }

    @Override
    public boolean isEncrypted() {
        if(secret != null && encryptedSecret != null) {
            throw new IllegalStateException("Cannot be in a encrypted and unencrypted state");
        }

        return encryptedSecret != null;
    }

    @Override
    public byte[] getSecretBytes() {
        return getSecret();
    }

    @Override
    public EncryptedData getEncryptedData() {
        return encryptedSecret;
    }

    @Override
    public EncryptionType getEncryptionType() {
        return new EncryptionType(EncryptionType.Deriver.ARGON2, EncryptionType.Crypter.AES_CBC_PKCS7);
    }

    @Override
    public long getCreationTimeMillis() {
        return 0;
    }

    public BtqMasterSecret encrypt(Key key) {
        if(encryptedSecret != null) {
            throw new IllegalArgumentException("Trying to encrypt twice");
        }
        if(secret == null) {
            throw new IllegalArgumentException("Secret data missing so cannot encrypt");
        }

        KeyCrypter keyCrypter = getEncryptionType().getCrypter().getKeyCrypter();
        EncryptedData encryptedSecretData = keyCrypter.encrypt(secret, null, key);

        BtqMasterSecret encrypted = new BtqMasterSecret(encryptedSecretData);
        encrypted.setId(getId());

        return encrypted;
    }

    public BtqMasterSecret decrypt(CharSequence password) {
        if(!isEncrypted()) {
            throw new IllegalStateException("Cannot decrypt unencrypted BTQ master secret");
        }

        KeyDeriver keyDeriver = getEncryptionType().getDeriver().getKeyDeriver(encryptedSecret.getKeySalt());
        Key key = keyDeriver.deriveKey(password);
        BtqMasterSecret decrypted = decrypt(key);
        decrypted.setId(getId());
        key.clear();

        return decrypted;
    }

    public BtqMasterSecret decrypt(Key key) {
        if(!isEncrypted()) {
            throw new IllegalStateException("Cannot decrypt unencrypted BTQ master secret");
        }

        KeyCrypter keyCrypter = getEncryptionType().getCrypter().getKeyCrypter();
        byte[] decrypted = keyCrypter.decrypt(encryptedSecret, key);
        BtqMasterSecret btqMasterSecret = new BtqMasterSecret(decrypted);
        btqMasterSecret.setId(getId());
        return btqMasterSecret;
    }

    public BtqMasterSecret copy() {
        BtqMasterSecret copy;
        if(isEncrypted()) {
            copy = new BtqMasterSecret(encryptedSecret.copy());
        } else {
            copy = new BtqMasterSecret(Arrays.copyOf(secret, secret.length));
        }

        copy.setId(getId());
        return copy;
    }

    public void clear() {
        if(secret != null) {
            Arrays.fill(secret, (byte)0);
        }
    }
}
