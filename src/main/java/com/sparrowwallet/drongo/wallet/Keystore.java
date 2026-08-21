package com.sparrowwallet.drongo.wallet;

import com.sparrowwallet.drongo.ExtendedKey;
import com.sparrowwallet.drongo.KeyDerivation;
import com.sparrowwallet.drongo.KeyPurpose;
import com.sparrowwallet.drongo.Network;
import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.btq.BtqDerivation;
import com.sparrowwallet.drongo.bip47.PaymentAddress;
import com.sparrowwallet.drongo.bip47.PaymentCode;
import com.sparrowwallet.drongo.crypto.*;
import com.sparrowwallet.drongo.policy.PolicyType;
import com.sparrowwallet.drongo.protocol.ScriptType;
import com.sparrowwallet.drongo.protocol.Sha256Hash;
import com.sparrowwallet.drongo.silentpayments.SilentPaymentScanAddress;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

public class Keystore extends Persistable {
    private static final Logger log = LoggerFactory.getLogger(Keystore.class);

    public static final String DEFAULT_LABEL = "Keystore 1";
    public static final int MAX_LABEL_LENGTH = 16;

    private String label;
    private KeystoreSource source = KeystoreSource.SW_WATCH;
    private WalletModel walletModel = WalletModel.SPARROW;
    private KeyDerivation keyDerivation;
    private ExtendedKey extendedPublicKey;
    private PaymentCode externalPaymentCode;
    private SilentPaymentScanAddress silentPaymentScanAddress;
    private byte[] deviceRegistration;
    private MasterPrivateExtendedKey masterPrivateExtendedKey;
    private DeterministicSeed seed;

    //Bitcoin Quantum custody: the 32-byte HKDF master secret and a cache of derived ML-DSA public keys.
    //BTQ has no public derivation, so public keys can only be produced while the secret is decrypted.
    private BtqMasterSecret btqMasterSecret;
    private final Map<KeyPurpose, List<byte[]>> btqPublicKeyCache = new LinkedHashMap<>();

    //For BIP47 keystores - not persisted but must be unencrypted to generate keys
    private transient ExtendedKey bip47ExtendedPrivateKey;

    //Avoid performing repeated expensive seed derivation checks
    private transient boolean extendedPublicKeyChecked;
    private transient boolean silentPaymentScanAddressChecked;

    public Keystore() {
        this(DEFAULT_LABEL);
    }

    public Keystore(String label) {
        this.label = label;
    }

    public String getLabel() {
        return label;
    }

    public String getBaseLabel() {
        if(walletModel != null && label.startsWith(walletModel.toDisplayString()) && label.substring(walletModel.toDisplayString().length()).matches("( \\d*)?$")) {
            return walletModel.toDisplayString();
        }
        return label.replaceAll(" \\d*$", "");
    }

    public String getScriptName() {
        String scriptName = label.replaceAll("[^\\p{L}\\p{N}]", "");
        return scriptName.isEmpty() ? "Keystore" : scriptName;
    }

    public void setLabel(String label) {
        this.label = label;
    }

    public KeystoreSource getSource() {
        return source;
    }

    public void setSource(KeystoreSource source) {
        this.source = source;
    }

    public WalletModel getWalletModel() {
        return walletModel;
    }

    public void setWalletModel(WalletModel walletModel) {
        this.walletModel = walletModel;
    }

    public KeyDerivation getKeyDerivation() {
        return keyDerivation;
    }

    public void setKeyDerivation(KeyDerivation keyDerivation) {
        this.keyDerivation = keyDerivation;
    }

    public ExtendedKey getExtendedPublicKey() {
        return extendedPublicKey;
    }

    public void setExtendedPublicKey(ExtendedKey extendedPublicKey) {
        this.extendedPublicKey = extendedPublicKey;
        this.extendedPublicKeyChecked = false;
    }

    public PaymentCode getExternalPaymentCode() {
        return externalPaymentCode;
    }

    public void setExternalPaymentCode(PaymentCode paymentCode) {
        this.externalPaymentCode = paymentCode;
    }

    public SilentPaymentScanAddress getSilentPaymentScanAddress() {
        return silentPaymentScanAddress;
    }

    public void setSilentPaymentScanAddress(SilentPaymentScanAddress silentPaymentScanAddress) {
        this.silentPaymentScanAddress = silentPaymentScanAddress;
        this.silentPaymentScanAddressChecked = false;
    }

    public byte[] getDeviceRegistration() {
        return deviceRegistration;
    }

    public void setDeviceRegistration(byte[] deviceRegistration) {
        this.deviceRegistration = deviceRegistration;
    }

    public boolean hasMasterPrivateExtendedKey() {
        return masterPrivateExtendedKey != null;
    }

    public MasterPrivateExtendedKey getMasterPrivateExtendedKey() {
        return masterPrivateExtendedKey;
    }

    public void setMasterPrivateExtendedKey(MasterPrivateExtendedKey masterPrivateExtendedKey) {
        this.masterPrivateExtendedKey = masterPrivateExtendedKey;
    }

    public boolean hasSeed() {
        return seed != null;
    }

    public DeterministicSeed getSeed() {
        return seed;
    }

    public void setSeed(DeterministicSeed seed) {
        this.seed = seed;
    }

    public boolean hasBtqMasterSecret() {
        return btqMasterSecret != null;
    }

    public BtqMasterSecret getBtqMasterSecret() {
        return btqMasterSecret;
    }

    public void setBtqMasterSecret(BtqMasterSecret btqMasterSecret) {
        this.btqMasterSecret = btqMasterSecret;
    }

    public boolean hasMasterPrivateKey() {
        return hasSeed() || hasMasterPrivateExtendedKey();
    }

    public boolean hasPrivateKey() {
        return hasMasterPrivateKey() || hasBtqMasterSecret() || (source == KeystoreSource.SW_PAYMENT_CODE && bip47ExtendedPrivateKey != null);
    }

    /**
     * The ML-DSA-44 public key for a BTQ custody wallet node, derived via HKDF from the master secret
     * and cached. BTQ has no public derivation, so an uncached key requires the decrypted master secret.
     * <p>
     * Returns null (never throws) when the key is uncached and the master secret is locked. This is safe:
     * a wallet can only receive at an address it already derived and registered (which required the
     * secret), so every <i>used</i> index is always cached; only unused gap-window addresses can be null.
     */
    public byte[] getBtqPublicKey(WalletNode walletNode) {
        return getBtqPublicKey(walletNode.getKeyPurpose(), walletNode.getIndex());
    }

    public byte[] getBtqPublicKey(KeyPurpose keyPurpose, int keyIndex) {
        synchronized(btqPublicKeyCache) {
            List<byte[]> cache = btqPublicKeyCache.computeIfAbsent(keyPurpose, purpose -> new ArrayList<>());
            if(keyIndex < cache.size() && cache.get(keyIndex) != null) {
                return cache.get(keyIndex);
            }

            if(btqMasterSecret == null || btqMasterSecret.isEncrypted()) {
                return null;
            }

            byte[] publicKey = BtqDerivation.derivePublicKey(btqMasterSecret.getSecret(), Network.get(), BtqDerivation.Chain.fromKeyPurpose(keyPurpose), keyIndex);
            while(cache.size() <= keyIndex) {
                cache.add(null);
            }
            cache.set(keyIndex, publicKey);
            return publicKey;
        }
    }

    /**
     * Merge cached ML-DSA public keys from another keystore into this one (e.g. from a decrypted signing
     * copy whose cache grew, back into the encrypted original so the growth persists). Public keys only.
     *
     * @return true if any new entries were added
     */
    public boolean mergeBtqPublicKeyCache(Keystore other) {
        boolean added = false;
        synchronized(btqPublicKeyCache) {
            synchronized(other.btqPublicKeyCache) {
                for(Map.Entry<KeyPurpose, List<byte[]>> entry : other.btqPublicKeyCache.entrySet()) {
                    List<byte[]> cache = btqPublicKeyCache.computeIfAbsent(entry.getKey(), purpose -> new ArrayList<>());
                    List<byte[]> otherCache = entry.getValue();
                    for(int keyIndex = 0; keyIndex < otherCache.size(); keyIndex++) {
                        byte[] publicKey = otherCache.get(keyIndex);
                        if(publicKey == null) {
                            continue;
                        }
                        while(cache.size() <= keyIndex) {
                            cache.add(null);
                        }
                        if(cache.get(keyIndex) == null) {
                            cache.set(keyIndex, publicKey);
                            added = true;
                        }
                    }
                }
            }
        }
        return added;
    }

    /**
     * Encode the public key cache for persistence: version byte, then per chain [purpose ordinal, uint16
     * count, count x 1312-byte keys]. Only the contiguous non-null prefix of each chain is written - the
     * format is positional, so encoding past a hole would re-index later keys on decode.
     */
    public byte[] encodeBtqPublicKeyCache() {
        synchronized(btqPublicKeyCache) {
            if(btqPublicKeyCache.isEmpty()) {
                return null;
            }
            java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
            out.write(1);
            for(Map.Entry<KeyPurpose, List<byte[]>> entry : btqPublicKeyCache.entrySet()) {
                List<byte[]> keys = new ArrayList<>();
                for(byte[] publicKey : entry.getValue()) {
                    if(publicKey == null) {
                        break;
                    }
                    keys.add(publicKey);
                }
                out.write(entry.getKey().ordinal());
                out.write((keys.size() >> 8) & 0xff);
                out.write(keys.size() & 0xff);
                for(byte[] publicKey : keys) {
                    out.writeBytes(publicKey);
                }
            }
            return out.toByteArray();
        }
    }

    /** Restore the public key cache from its persisted encoding. Unknown versions are ignored. */
    public void decodeBtqPublicKeyCache(byte[] encoded) {
        if(encoded == null || encoded.length < 1 || encoded[0] != 1) {
            return;
        }
        int offset = 1;
        while(offset + 3 <= encoded.length) {
            KeyPurpose keyPurpose = KeyPurpose.values()[encoded[offset] & 0xff];
            int count = ((encoded[offset + 1] & 0xff) << 8) | (encoded[offset + 2] & 0xff);
            offset += 3;
            List<byte[]> cache = btqPublicKeyCache.computeIfAbsent(keyPurpose, purpose -> new ArrayList<>());
            for(int keyIndex = 0; keyIndex < count && offset + 1312 <= encoded.length; keyIndex++) {
                byte[] publicKey = Arrays.copyOfRange(encoded, offset, offset + 1312);
                offset += 1312;
                while(cache.size() <= keyIndex) {
                    cache.add(null);
                }
                if(cache.get(keyIndex) == null) {
                    cache.set(keyIndex, publicKey);
                }
            }
        }
    }

    /** The 32-byte ML-DSA key seed for a BTQ wallet node, for signing. The caller must zeroize it after use. */
    public byte[] getBtqKeySeed(KeyPurpose keyPurpose, int keyIndex) {
        if(btqMasterSecret == null || btqMasterSecret.isEncrypted()) {
            throw new IllegalStateException("BTQ master secret is not available to derive key seeds");
        }

        return BtqDerivation.deriveKeySeed(btqMasterSecret.getSecret(), Network.get(), BtqDerivation.Chain.fromKeyPurpose(keyPurpose), keyIndex);
    }

    public boolean needsPassphrase() {
        if(seed != null) {
            return seed.needsPassphrase();
        }

        return false;
    }

    public PaymentCode getPaymentCode() {
        DeterministicKey bip47Key = bip47ExtendedPrivateKey.getKey();
        return new PaymentCode(bip47Key.getPubKey(), bip47Key.getChainCode());
    }

    public ExtendedKey getBip47ExtendedPrivateKey() {
        return bip47ExtendedPrivateKey;
    }

    public void setBip47ExtendedPrivateKey(ExtendedKey bip47ExtendedPrivateKey) {
        this.bip47ExtendedPrivateKey = bip47ExtendedPrivateKey;
    }

    public PaymentAddress getPaymentAddress(KeyPurpose keyPurpose, int index) {
        List<ChildNumber> derivation = keyDerivation.getDerivation();
        ChildNumber derivationStart = keyDerivation.getDerivation().isEmpty() ? ChildNumber.ZERO_HARDENED : keyDerivation.getDerivation().get(derivation.size() - 1);
        DeterministicKey privateKey = bip47ExtendedPrivateKey.getKey(List.of(derivationStart, new ChildNumber(keyPurpose == KeyPurpose.SEND ? 0 : index)));
        return new PaymentAddress(externalPaymentCode, keyPurpose == KeyPurpose.SEND ? index : 0, privateKey.getPrivKeyBytes());
    }

    public DeterministicKey getMasterPrivateKey() throws MnemonicException {
        if(seed == null && masterPrivateExtendedKey == null) {
            throw new IllegalArgumentException("Keystore does not contain a master private key, or seed to derive one from");
        }

        if(seed != null) {
            if(seed.isEncrypted()) {
                throw new IllegalArgumentException("Seed is encrypted");
            }

            return HDKeyDerivation.createMasterPrivateKey(seed.getSeedBytes());
        }

        if(masterPrivateExtendedKey.isEncrypted()) {
            throw new IllegalArgumentException("Master private key is encrypted");
        }

        return masterPrivateExtendedKey.getPrivateKey();
    }

    public ExtendedKey getExtendedMasterPrivateKey() throws MnemonicException {
        return new ExtendedKey(getMasterPrivateKey(), new byte[4], ChildNumber.ZERO);
    }

    public ExtendedKey getExtendedMasterPublicKey() throws MnemonicException {
        return new ExtendedKey(getMasterPrivateKey().dropPrivateBytes(), new byte[4], ChildNumber.ZERO);
    }

    public ExtendedKey getExtendedPrivateKey() throws MnemonicException {
        return getExtendedPrivateKey(true);
    }

    public ExtendedKey getExtendedPrivateKey(boolean resetPathToDerivedDepth) throws MnemonicException {
        List<ChildNumber> derivation = getKeyDerivation().getDerivation();
        DeterministicKey derivedKey = getExtendedMasterPrivateKey().getKey(derivation);
        ExtendedKey xprv = new ExtendedKey(derivedKey, derivedKey.getParentFingerprint(), derivation.isEmpty() ? ChildNumber.ZERO : derivation.get(derivation.size() - 1));
        if(resetPathToDerivedDepth) {
            //Recreate from xprv string to reset path to single ChildNumber at the derived depth
            return ExtendedKey.fromDescriptor(xprv.toString());
        } else {
            return xprv;
        }
    }

    public ECKey getKey(WalletNode walletNode) throws MnemonicException {
        if(silentPaymentScanAddress != null && walletNode.getWallet().getPolicyType() == PolicyType.SINGLE_SP) {
            ECKey spendPrivKey = getSpendPrivateKey(Collections.emptyMap());
            byte[] tweak = walletNode.getSilentPaymentTweak();
            if(tweak == null) {
                if(walletNode.isPurposeNode()) {
                    return spendPrivKey;
                }
                throw new IllegalStateException("Silent payment tweak is required for address node " + walletNode.getDerivationPath());
            }
            return spendPrivKey.addPrivate(ECKey.fromPrivate(tweak));
        }

        if(source == KeystoreSource.SW_PAYMENT_CODE) {
            try {
                if(walletNode.getKeyPurpose() != KeyPurpose.RECEIVE) {
                    throw new IllegalArgumentException("Cannot get private key for non-receive chain");
                }

                PaymentAddress paymentAddress = getPaymentAddress(walletNode.getKeyPurpose(), walletNode.getIndex());
                return paymentAddress.getReceiveECKey();
            } catch(IllegalArgumentException e) {
                throw new IllegalArgumentException("Invalid payment code " + externalPaymentCode, e);
            } catch(Exception e) {
                log.error("Cannot get receive private key at index " + walletNode.getIndex() + " for payment code " + externalPaymentCode, e);
            }
        }

        ExtendedKey extendedPrivateKey = getExtendedPrivateKey();
        List<ChildNumber> derivation = new ArrayList<>();
        derivation.add(extendedPrivateKey.getKeyChildNumber());
        derivation.addAll(walletNode.getDerivation());
        return extendedPrivateKey.getKey(derivation);
    }

    public ECKey getPubKey(WalletNode walletNode) {
        if(silentPaymentScanAddress != null && walletNode.getWallet().getPolicyType() == PolicyType.SINGLE_SP) {
            ECKey spendKey = silentPaymentScanAddress.getSpendKey();
            byte[] tweak = walletNode.getSilentPaymentTweak();
            if(tweak == null) {
                if(walletNode.isPurposeNode()) {
                    return spendKey;
                }
                throw new IllegalStateException("Silent payment tweak is required for address node " + walletNode.getDerivationPath());
            }
            ECKey tweakPoint = ECKey.fromPublicOnly(ECKey.fromPrivate(tweak));
            return spendKey.add(tweakPoint, true);
        }

        if(source == KeystoreSource.SW_PAYMENT_CODE) {
            try {
                PaymentAddress paymentAddress = getPaymentAddress(walletNode.getKeyPurpose(), walletNode.getIndex());
                return walletNode.getKeyPurpose() == KeyPurpose.RECEIVE ? ECKey.fromPublicOnly(paymentAddress.getReceiveECKey()) : paymentAddress.getSendECKey();
            } catch(IllegalArgumentException e) {
                throw new IllegalArgumentException("Invalid payment code " + externalPaymentCode, e);
            } catch(Exception e) {
                log.error("Cannot get receive private key at index " + walletNode.getIndex() + " for payment code " + externalPaymentCode, e);
            }
        }

        List<ChildNumber> derivation = new ArrayList<>();
        derivation.add(extendedPublicKey.getKeyChildNumber());
        derivation.addAll(walletNode.getDerivation());
        return extendedPublicKey.getKey(derivation);
    }

    public KeyDerivation getDerivation(KeyPurpose keyPurpose, int keyIndex) {
        return getKeyDerivation().extend(keyPurpose.getPathIndex()).extend(new ChildNumber(keyIndex));
    }

    public ECKey getPubKeyForDerivation(KeyDerivation keyDerivation) {
        if(keyDerivation != null && extendedPublicKey != null) {
            List<ChildNumber> derivation = keyDerivation.getDerivation();
            String fingerprint = Utils.bytesToHex(this.extendedPublicKey.getKey().getFingerprint());
            if(derivation.size() > this.keyDerivation.getDerivation().size()) {
                List<ChildNumber> xpubDerivation = derivation.subList(0, this.keyDerivation.getDerivation().size());
                if(xpubDerivation.equals(this.keyDerivation.getDerivation())) {
                    derivation = derivation.subList(this.keyDerivation.getDerivation().size(), derivation.size());
                    fingerprint = this.keyDerivation.getMasterFingerprint();
                }
            }

            if(derivation.size() == 2 && KeyPurpose.fromChildNumber(derivation.get(0)) != null && fingerprint.equals(keyDerivation.getMasterFingerprint())) {
                return getPubKey(new WalletNode(KeyDerivation.writePath(derivation)));
            }
        }

        return null;
    }

    public ECKey getSpendPrivateKey(Map<ECKey, KeyDerivation> spendDerivations) throws MnemonicException {
        String masterFingerprint = getKeyDerivation().getMasterFingerprint();
        for(Map.Entry<ECKey, KeyDerivation> entry : spendDerivations.entrySet()) {
            if(masterFingerprint.equals(entry.getValue().getMasterFingerprint())) {
                DeterministicKey derivedKey = getExtendedMasterPrivateKey().getKey(entry.getValue().getDerivation());
                ECKey spendPrivKey = ECKey.fromPrivate(derivedKey.getPrivKeyBytes(), true);

                if(!Arrays.equals(spendPrivKey.getPubKey(), entry.getKey().getPubKey())) {
                    throw new IllegalStateException("Derived spend private key does not match PSBT spend public key");
                }

                return spendPrivKey;
            }
        }

        List<ChildNumber> spendDerivation = KeyDerivation.getBip352SpendDerivation(getKeyDerivation().getDerivation());
        DeterministicKey derivedKey = getExtendedMasterPrivateKey().getKey(spendDerivation);
        ECKey spendPrivKey = ECKey.fromPrivate(derivedKey.getPrivKeyBytes(), true);

        ECKey expectedSpendPubKey = getSilentPaymentScanAddress().getSpendKey();
        if(!Arrays.equals(spendPrivKey.getPubKey(), expectedSpendPubKey.getPubKey())) {
            throw new IllegalStateException("Derived spend private key does not match keystore spend public key");
        }

        return spendPrivKey;
    }

    public boolean isValid() {
        try {
            checkKeystore();
        } catch(InvalidKeystoreException e) {
            return false;
        }

        return true;
    }

    public void checkKeystore() throws InvalidKeystoreException {
        if(label == null) {
            throw new InvalidKeystoreException("No label specified");
        }

        if(source == null) {
            throw new InvalidKeystoreException("No source specified");
        }

        if(walletModel == null) {
            throw new InvalidKeystoreException("No wallet model specified");
        }

        if(keyDerivation == null) {
            throw new InvalidKeystoreException("No key derivation specified");
        }

        if(extendedPublicKey == null && silentPaymentScanAddress == null && source != KeystoreSource.SW_BTQ_SEED) {
            throw new InvalidKeystoreException("No extended public key or silent payment scan address specified");
        }

        if(source == KeystoreSource.SW_BTQ_SEED && btqMasterSecret == null) {
            throw new InvalidKeystoreException("Source of " + source + " but no BTQ master secret is present");
        }

        if(label.isEmpty()) {
            throw new InvalidKeystoreException("Label too short");
        }

        if(label.replace(" ", "").length() > MAX_LABEL_LENGTH) {
            throw new InvalidKeystoreException("Label too long");
        }

        if(keyDerivation.getDerivationPath() == null || keyDerivation.getDerivationPath().isEmpty() || !KeyDerivation.isValid(keyDerivation.getDerivationPath())) {
            throw new InvalidKeystoreException("Invalid key derivation path of " + keyDerivation.getDerivationPath());
        }

        if(keyDerivation.getMasterFingerprint() == null || keyDerivation.getMasterFingerprint().length() != 8 || !Utils.isHex(keyDerivation.getMasterFingerprint())) {
            throw new InvalidKeystoreException("Invalid master fingerprint of " + keyDerivation.getMasterFingerprint());
        }

        if(source == KeystoreSource.SW_SEED) {
            if(seed == null && masterPrivateExtendedKey == null) {
                throw new InvalidKeystoreException("Source of " + source + " but no seed or master private key is present");
            }

            if(!extendedPublicKeyChecked && extendedPublicKey != null && ((seed != null && !seed.isEncrypted()) || (masterPrivateExtendedKey != null && !masterPrivateExtendedKey.isEncrypted()))) {
                try {
                    List<ChildNumber> derivation = getKeyDerivation().getDerivation();
                    DeterministicKey derivedKey = getExtendedMasterPrivateKey().getKey(derivation);
                    DeterministicKey derivedKeyPublicOnly = derivedKey.dropPrivateBytes().dropParent();
                    ExtendedKey xpub = new ExtendedKey(derivedKeyPublicOnly, derivedKey.getParentFingerprint(), derivation.isEmpty() ? ChildNumber.ZERO : derivation.get(derivation.size() - 1));
                    if(!xpub.equals(getExtendedPublicKey())) {
                        throw new InvalidKeystoreException("Specified extended public key does not match public key derived from seed");
                    }
                    extendedPublicKeyChecked = true;
                } catch(MnemonicException e) {
                    throw new InvalidKeystoreException("Invalid mnemonic specified for seed", e);
                }
            }

            if(!silentPaymentScanAddressChecked && silentPaymentScanAddress != null && ((seed != null && !seed.isEncrypted()) || (masterPrivateExtendedKey != null && !masterPrivateExtendedKey.isEncrypted()))) {
                try {
                    List<ChildNumber> derivation = getKeyDerivation().getDerivation();
                    DeterministicKey derivedScanKey = getExtendedMasterPrivateKey().getKey(KeyDerivation.getBip352ScanDerivation(derivation));
                    DeterministicKey derivedSpendKey = getExtendedMasterPrivateKey().getKey(KeyDerivation.getBip352SpendDerivation(derivation));
                    SilentPaymentScanAddress derivedScanAddress = new SilentPaymentScanAddress(derivedScanKey, derivedSpendKey);
                    if(!derivedScanAddress.equals(getSilentPaymentScanAddress())) {
                        throw new InvalidKeystoreException("Specified silent payments scan address does not match scan and spend keys derived from seed");
                    }
                    silentPaymentScanAddressChecked = true;
                } catch(MnemonicException e) {
                    throw new InvalidKeystoreException("Invalid mnemonic specified for seed", e);
                }
            }
        }

        if(source == KeystoreSource.SW_PAYMENT_CODE) {
            if(externalPaymentCode == null) {
                throw new InvalidKeystoreException("Source of " + source + " but no payment code is present");
            }

            if(bip47ExtendedPrivateKey == null) {
                throw new InvalidKeystoreException("Source of " + source + " but no extended private key is present");
            }
        }
    }

    public Keystore copy() {
        Keystore copy = new Keystore(label);
        copy.setId(getId());
        copy.setSource(source);
        copy.setWalletModel(walletModel);
        if(keyDerivation != null) {
            copy.setKeyDerivation(keyDerivation.copy());
        }
        if(extendedPublicKey != null) {
            copy.setExtendedPublicKey(extendedPublicKey.copy());
        }
        if(masterPrivateExtendedKey != null) {
            copy.setMasterPrivateExtendedKey(masterPrivateExtendedKey.copy());
        }
        if(seed != null) {
            copy.setSeed(seed.copy());
        }
        if(btqMasterSecret != null) {
            copy.setBtqMasterSecret(btqMasterSecret.copy());
        }
        synchronized(btqPublicKeyCache) {
            for(Map.Entry<KeyPurpose, List<byte[]>> cacheEntry : btqPublicKeyCache.entrySet()) {
                copy.btqPublicKeyCache.put(cacheEntry.getKey(), new ArrayList<>(cacheEntry.getValue()));
            }
        }
        if(externalPaymentCode != null) {
            copy.setExternalPaymentCode(externalPaymentCode.copy());
        }
        if(bip47ExtendedPrivateKey != null) {
            copy.setBip47ExtendedPrivateKey(bip47ExtendedPrivateKey.copy());
        }
        if(silentPaymentScanAddress != null) {
            copy.setSilentPaymentScanAddress(silentPaymentScanAddress.copy());
        }
        return copy;
    }

    public static Keystore fromSeed(DeterministicSeed seed, PolicyType policyType, List<ChildNumber> derivation) throws MnemonicException {
        Keystore keystore = new Keystore();
        keystore.setSeed(seed);
        keystore.setLabel(seed.getType().name());
        rederiveKeystoreFromMaster(keystore, policyType, derivation);
        return keystore;
    }

    public static Keystore fromMasterPrivateExtendedKey(MasterPrivateExtendedKey masterPrivateExtendedKey, PolicyType policyType, List<ChildNumber> derivation) throws MnemonicException {
        Keystore keystore = new Keystore();
        keystore.setMasterPrivateExtendedKey(masterPrivateExtendedKey);
        keystore.setLabel("Master Key");
        rederiveKeystoreFromMaster(keystore, policyType, derivation);
        return keystore;
    }

    /**
     * Create a Bitcoin Quantum custody keystore from a 32-byte master secret. The keystore identifies
     * itself with a synthetic master fingerprint (the first 4 bytes of SHA-256 of the receive-chain
     * index-0 ML-DSA public key on the given network) since BTQ has no BIP32 tree.
     */
    public static Keystore fromBtqMasterSecret(byte[] masterSecret, Network network) {
        Keystore keystore = new Keystore();
        keystore.setBtqMasterSecret(new BtqMasterSecret(masterSecret));
        keystore.setLabel("BTQ Custody");
        keystore.setSource(KeystoreSource.SW_BTQ_SEED);
        keystore.setWalletModel(WalletModel.BTQ_CORE);

        byte[] receiveKey = BtqDerivation.derivePublicKey(masterSecret, network, BtqDerivation.Chain.RECEIVE, 0);
        byte[] fingerprint = Arrays.copyOf(Sha256Hash.hash(receiveKey), 4);
        keystore.setKeyDerivation(new KeyDerivation(Utils.bytesToHex(fingerprint), "m/0'"));

        keystore.warmBtqPublicKeyCache(network, BTQ_CACHE_WARM_INDEXES);
        return keystore;
    }

    /**
     * Derive and cache the first ML-DSA public keys of both chains while the master secret is available.
     * BTQ has no public derivation, so the cache is what keeps addresses displayable while the keystore
     * is encrypted; it is carried through copies and re-warmed on decrypt.
     */
    public void warmBtqPublicKeyCache(Network network, int keysPerChain) {
        for(KeyPurpose keyPurpose : KeyPurpose.DEFAULT_PURPOSES) {
            warmBtqPublicKeyCache(network, keyPurpose, keysPerChain);
        }
    }

    /** Derive and cache the first {@code keyCount} ML-DSA public keys of one chain while the secret is available. */
    public void warmBtqPublicKeyCache(Network network, KeyPurpose keyPurpose, int keyCount) {
        if(btqMasterSecret == null || btqMasterSecret.isEncrypted()) {
            return;
        }
        synchronized(btqPublicKeyCache) {
            List<byte[]> cache = btqPublicKeyCache.computeIfAbsent(keyPurpose, purpose -> new ArrayList<>());
            int target = Math.max(keyCount, cache.size());
            for(int keyIndex = 0; keyIndex < target; keyIndex++) {
                if(keyIndex >= cache.size() || cache.get(keyIndex) == null) {
                    byte[] publicKey = BtqDerivation.derivePublicKey(btqMasterSecret.getSecret(), network, BtqDerivation.Chain.fromKeyPurpose(keyPurpose), keyIndex);
                    while(cache.size() <= keyIndex) {
                        cache.add(null);
                    }
                    cache.set(keyIndex, publicKey);
                }
            }
        }
    }

    private static void rederiveKeystoreFromMaster(Keystore keystore, PolicyType policyType, List<ChildNumber> derivation) throws MnemonicException {
        ExtendedKey xprv = keystore.getExtendedMasterPrivateKey();
        String masterFingerprint = Utils.bytesToHex(xprv.getKey().getFingerprint());

        keystore.setSource(KeystoreSource.SW_SEED);
        keystore.setWalletModel(WalletModel.SPARROW);
        keystore.setKeyDerivation(new KeyDerivation(masterFingerprint, KeyDerivation.writePath(derivation)));

        if(policyType == PolicyType.SINGLE_SP) {
            DeterministicKey scanKey = xprv.getKey(KeyDerivation.getBip352ScanDerivation(derivation));
            DeterministicKey spendKey = xprv.getKey(KeyDerivation.getBip352SpendDerivation(derivation));
            SilentPaymentScanAddress spScanAddress = new SilentPaymentScanAddress(ECKey.fromPrivate(scanKey.getPrivKey()), ECKey.fromPublicOnly(spendKey));
            keystore.setSilentPaymentScanAddress(spScanAddress);
        } else {
            DeterministicKey derivedKey = xprv.getKey(derivation);
            DeterministicKey derivedKeyPublicOnly = derivedKey.dropPrivateBytes().dropParent();
            ExtendedKey xpub = new ExtendedKey(derivedKeyPublicOnly, derivedKey.getParentFingerprint(), derivation.isEmpty() ? ChildNumber.ZERO : derivation.get(derivation.size() - 1));
            keystore.setExtendedPublicKey(ExtendedKey.fromDescriptor(xpub.toString()));

            int account = ScriptType.getScriptTypesForPolicyType(PolicyType.SINGLE_HD).stream()
                    .mapToInt(scriptType -> scriptType.getAccount(keystore.getKeyDerivation().getDerivationPath())).filter(idx -> idx > -1).findFirst().orElse(0);
            List<ChildNumber> bip47Derivation = KeyDerivation.getBip47Derivation(account);
            DeterministicKey bip47Key = xprv.getKey(bip47Derivation);
            ExtendedKey bip47ExtendedPrivateKey = new ExtendedKey(bip47Key, bip47Key.getParentFingerprint(), bip47Derivation.get(bip47Derivation.size() - 1));
            keystore.setBip47ExtendedPrivateKey(ExtendedKey.fromDescriptor(bip47ExtendedPrivateKey.toString()));
        }
    }

    public boolean isEncrypted() {
        return (seed != null && seed.isEncrypted()) || (masterPrivateExtendedKey != null && masterPrivateExtendedKey.isEncrypted()) || (btqMasterSecret != null && btqMasterSecret.isEncrypted());
    }

    public void encrypt(Key key) {
        if(hasSeed() && !seed.isEncrypted()) {
            seed = seed.encrypt(key);
        }
        if(hasMasterPrivateExtendedKey() && !masterPrivateExtendedKey.isEncrypted()) {
            masterPrivateExtendedKey = masterPrivateExtendedKey.encrypt(key);
        }
        if(hasBtqMasterSecret() && !btqMasterSecret.isEncrypted()) {
            //Last moment the secret is available: ensure the public key cache covers the gap window so
            //addresses stay displayable while encrypted, regardless of how this keystore was assembled
            warmBtqPublicKeyCache(Network.get(), BTQ_CACHE_WARM_INDEXES);
            btqMasterSecret = btqMasterSecret.encrypt(key);
        }
    }

    //Pre-derived ML-DSA public keys per chain, covering Sparrow's default gap limit
    public static final int BTQ_CACHE_WARM_INDEXES = 21;

    public void decrypt(CharSequence password) {
        if(hasSeed() && seed.isEncrypted()) {
            seed = seed.decrypt(password);
        }
        if(hasMasterPrivateExtendedKey() && masterPrivateExtendedKey.isEncrypted()) {
            masterPrivateExtendedKey = masterPrivateExtendedKey.decrypt(password);
        }
        if(hasBtqMasterSecret() && btqMasterSecret.isEncrypted()) {
            btqMasterSecret = btqMasterSecret.decrypt(password);
            warmBtqPublicKeyCache(Network.get(), BTQ_CACHE_WARM_INDEXES);
        }
    }

    public void decrypt(Key key) {
        if(hasSeed() && seed.isEncrypted()) {
            seed = seed.decrypt(key);
        }
        if(hasMasterPrivateExtendedKey() && masterPrivateExtendedKey.isEncrypted()) {
            masterPrivateExtendedKey = masterPrivateExtendedKey.decrypt(key);
        }
        if(hasBtqMasterSecret() && btqMasterSecret.isEncrypted()) {
            btqMasterSecret = btqMasterSecret.decrypt(key);
            warmBtqPublicKeyCache(Network.get(), BTQ_CACHE_WARM_INDEXES);
        }
    }

    public void clearPrivate() {
        if(hasSeed()) {
            seed.clear();
        }
        if(hasMasterPrivateExtendedKey()) {
            masterPrivateExtendedKey.clear();
        }
        if(hasBtqMasterSecret()) {
            btqMasterSecret.clear();
        }
    }
}
