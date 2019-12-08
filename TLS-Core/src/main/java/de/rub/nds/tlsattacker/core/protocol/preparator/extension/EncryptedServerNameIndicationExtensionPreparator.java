/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.DigestAlgorithm;
import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.constants.HKDFAlgorithm;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.crypto.HKDFunction;
import de.rub.nds.tlsattacker.core.crypto.ec.ForgivingX25519Curve;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.exceptions.PreparationException;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EncryptedServerNameIndicationExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareEntry;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareStoreEntry;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.esni.ClientEsniInnerPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ExtensionSerializer;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.KeyShareEntrySerializer;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.esni.ClientEsniInnerSerializer;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import de.rub.nds.tlsattacker.core.workflow.chooser.DefaultChooser;

public class EncryptedServerNameIndicationExtensionPreparator extends
        ExtensionPreparator<EncryptedServerNameIndicationExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();
    private final Chooser chooser;
    private final EncryptedServerNameIndicationExtensionMessage msg;
    private ByteArrayOutputStream streamClientEsniInnerBytes;

    public EncryptedServerNameIndicationExtensionPreparator(Chooser chooser,
            EncryptedServerNameIndicationExtensionMessage message,
            ExtensionSerializer<EncryptedServerNameIndicationExtensionMessage> serializer) {
        super(chooser, message, serializer);
        this.msg = message;
        this.chooser = chooser;
        this.streamClientEsniInnerBytes = new ByteArrayOutputStream();
    }

    @Override
    public void prepareExtensionContent() {
        LOGGER.debug("Preparing EncryptedServerNameIndicationExtension");

        prepareClientEsniInner(msg);
        prepareClientEsniInnerBytes(msg);

        prepareCipherSuite(msg);
        prepareServerPublicKey(msg);

        // TODO: Add support for additional groups
        prepareKeyShareEntry(msg);

        prepareRecordBytes(msg);
        prepareRecordDigest(msg);
        prepareRecordDigestLength(msg);

        prepateClientRandom(msg);
        prepareEsniContents(msg);
        prepareEsniContentsHash(msg);
        prepareSharedSecret(msg);
        prepareMasterSecret(msg);

        // TODO: Add support for additional CipherSuite
        prepareKey(msg);
        prepareIv(msg);
        prepareClientHelloKeyShare(msg);
        prepereEncryptedSni(msg);
        prepereEncryptedSniLength(msg);
    }

    @Override
    public void afterPrepareExtensionContent() {
        LOGGER.debug("Afterpreparing EncryptedServerNameIndicationExtension");
        prepateClientRandom(msg);
        prepareEsniContents(msg);
        prepareEsniContentsHash(msg);
        prepareSharedSecret(msg);
        prepareMasterSecret(msg);
        prepareKey(msg);
        prepareIv(msg);
        prepareClientHelloKeyShare(msg);
        prepereEncryptedSni(msg);
        prepereEncryptedSniLength(msg);
    }

    private void prepareClientEsniInner(EncryptedServerNameIndicationExtensionMessage msg) {
        ClientEsniInnerPreparator clientEsniInnerPreparator = new ClientEsniInnerPreparator(this.chooser,
                msg.getClientEsniInner());
        clientEsniInnerPreparator.prepare();
        ClientEsniInnerSerializer serializer = new ClientEsniInnerSerializer(msg.getClientEsniInner());
        try {
            this.streamClientEsniInnerBytes.write(serializer.serialize());
        } catch (IOException e) {
            e.printStackTrace();
            // System.err.println(e.getMessage());
            throw new PreparationException("Could not write byte[] from ClientEsniInner", e);
        }
        msg.setClientEsniInnerBytes(streamClientEsniInnerBytes.toByteArray());
    }

    private void prepareClientEsniInnerBytes(EncryptedServerNameIndicationExtensionMessage msg) {

        msg.setClientEsniInnerBytes(streamClientEsniInnerBytes.toByteArray());
        LOGGER.debug("clientEsniInnerBytes: "
                + ArrayConverter.bytesToHexString(msg.getClientEsniInnerBytes().getValue()));
    }

    private void prepareServerPublicKey(EncryptedServerNameIndicationExtensionMessage msg) {
        byte[] serverPublicKey = ((DefaultChooser) chooser).getEsniServerKeyShareEntryList().get(0);
        msg.getEncryptedSniComputation().setServerPublicKey(serverPublicKey);
        LOGGER.debug("ServerPublicKey: "
                + ArrayConverter.bytesToHexString(msg.getEncryptedSniComputation().getServerPublicKey().getValue()));
    }

    private void prepareCipherSuite(EncryptedServerNameIndicationExtensionMessage msg) {
        // TODO read form context
        msg.setCipherSuite(msg.getCipherSuiteConfig());
    }

    private void prepareRecordBytes(EncryptedServerNameIndicationExtensionMessage msg) {
        // TODO read form context
        byte[] recordBytes = chooser.getEsniRecordBytes();
        msg.getEncryptedSniComputation().setRecordBytes(recordBytes);
        LOGGER.debug("RecordBytes: "
                + ArrayConverter.bytesToHexString(msg.getEncryptedSniComputation().getRecordBytes()));
    }

    private void prepareKeyShareEntry(EncryptedServerNameIndicationExtensionMessage msg) {
        KeyShareEntry keyShareEntry = msg.getKeyShareEntry();
        KeyShareEntryPreparator keyShareEntryPreparator = new KeyShareEntryPreparator(chooser, keyShareEntry);
        keyShareEntryPreparator.prepare();
        LOGGER.debug("ClientPrivateKey: "
                + ArrayConverter.bytesToHexString(msg.getKeyShareEntry().getPrivateKey().toByteArray()));
        LOGGER.debug("ClientPublicKey: "
                + ArrayConverter.bytesToHexString(msg.getKeyShareEntry().getPublicKey().getValue()));

    }

    private void prepareRecordDigest(EncryptedServerNameIndicationExtensionMessage msg) {
        byte[] cipherSuite = msg.getCipherSuite().getValue();
        if (!Arrays.equals(cipherSuite, CipherSuite.TLS_AES_128_GCM_SHA256.getByteValue())) {
            LOGGER.error("CipherSuite not supported. Only TLS_AES_128_GCM_SHA256 is supportet yet.");
            throw new PreparationException("CipherSuite not supported yet.");
        }
        byte[] recordHash = null;
        byte[] record = msg.getEncryptedSniComputation().getRecordBytes().getValue();

        DigestAlgorithm algorithm = AlgorithmResolver.getDigestAlgorithm(ProtocolVersion.TLS13,
                CipherSuite.TLS_AES_128_GCM_SHA256);
        MessageDigest messageDigest = null;
        try {
            messageDigest = MessageDigest.getInstance(algorithm.getJavaName());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            // System.err.println(e.getMessage());
            throw new PreparationException("Could not prepare RecordDigest", e);
        }
        recordHash = messageDigest.digest(record);
        msg.setRecordDigest(recordHash);
        LOGGER.debug("RecordDigest: " + ArrayConverter.bytesToHexString(msg.getRecordDigest().getValue()));
    }

    private void prepareRecordDigestLength(EncryptedServerNameIndicationExtensionMessage msg) {
        msg.setRecordDigestLength(msg.getRecordDigest().getValue().length);
        LOGGER.debug("RecordDigestLength: " + msg.getRecordDigestLength().getValue());
    }

    private void prepateClientRandom(EncryptedServerNameIndicationExtensionMessage msg) {
        byte[] clienRandom = chooser.getClientRandom();
        msg.getEncryptedSniComputation().setClientHelloRandom(clienRandom);
        LOGGER.debug("ClientHello: " + ArrayConverter.bytesToHexString(clienRandom));
    }

    private void prepareEsniContents(EncryptedServerNameIndicationExtensionMessage msg) {
        byte[] contents = generateEsniContents(msg);
        msg.getEncryptedSniComputation().setEsniContents(contents);
        LOGGER.debug("EsniContents: "
                + ArrayConverter.bytesToHexString(msg.getEncryptedSniComputation().getEsniContents().getValue()));
    }

    private void prepareEsniContentsHash(EncryptedServerNameIndicationExtensionMessage msg) {
        byte[] contentsHash = null;
        byte[] contents = msg.getEncryptedSniComputation().getEsniContents().getValue();

        DigestAlgorithm algorithm = AlgorithmResolver.getDigestAlgorithm(ProtocolVersion.TLS13,
                CipherSuite.TLS_AES_128_GCM_SHA256);
        MessageDigest messageDigest = null;
        try {
            messageDigest = MessageDigest.getInstance(algorithm.getJavaName());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            // System.err.println(e.getMessage());
            throw new PreparationException("Could not prepare esniContentsHash", e);
        }
        contentsHash = messageDigest.digest(contents);
        msg.getEncryptedSniComputation().setEsniContentsHash(contentsHash);
        LOGGER.debug("EsniContentsHash: "
                + ArrayConverter.bytesToHexString(msg.getEncryptedSniComputation().getEsniContentsHash().getValue()));
    }

    private void prepareSharedSecret(EncryptedServerNameIndicationExtensionMessage msg) {
        byte[] group = msg.getKeyShareEntry().getGroup().getValue();
        if (!Arrays.equals(group, new byte[] { (byte) 0x00, (byte) 0x1d })) {
            LOGGER.error("NamedGroup not supported. Only DHEC Curve X25519 is supportet yet.");
            throw new PreparationException("NamedGroup not supported yet.");
        }

        byte[] sk = msg.getKeyShareEntry().getPrivateKey().toByteArray();
        byte[] pk = msg.getEncryptedSniComputation().getServerPublicKey().getValue();
        byte[] sharedSecret = ForgivingX25519Curve.computeSharedSecret(sk, pk);
        msg.getEncryptedSniComputation().setSharedSecret(sharedSecret);
        LOGGER.debug("SharedSecret: "
                + ArrayConverter.bytesToHexString(msg.getEncryptedSniComputation().getSharedSecret().getValue()));
    }

    private void prepareMasterSecret(EncryptedServerNameIndicationExtensionMessage msg) {
        byte[] masterSecret = null;
        byte[] sharedSecret = msg.getEncryptedSniComputation().getSharedSecret().getValue();
        CipherSuite cipherSuite = CipherSuite.TLS_AES_128_GCM_SHA256;
        HKDFAlgorithm hkdfAlgortihm = AlgorithmResolver.getHKDFAlgorithm(cipherSuite);
        try {
            masterSecret = HKDFunction.extract(hkdfAlgortihm, null, sharedSecret);
        } catch (CryptoException e) {
            e.printStackTrace();
            // System.err.println(e.getMessage());
            throw new PreparationException("Could not prepare MasterSecret", e);

        }
        msg.getEncryptedSniComputation().setMasterSecret(masterSecret);
        LOGGER.debug("MasterSecret: "
                + ArrayConverter.bytesToHexString(msg.getEncryptedSniComputation().getMasterSecret().getValue()));
    }

    private void prepareKey(EncryptedServerNameIndicationExtensionMessage msg) {
        byte[] key = null;
        byte[] masterSecret = msg.getEncryptedSniComputation().getMasterSecret().getValue();
        String labelIn = "esni key";
        byte[] hashIn = msg.getEncryptedSniComputation().getEsniContentsHash().getValue();
        CipherSuite cipherSuite = CipherSuite.TLS_AES_128_GCM_SHA256;
        HKDFAlgorithm hkdfAlgortihm = AlgorithmResolver.getHKDFAlgorithm(cipherSuite);
        int keyLen = 16;
        try {
            key = HKDFunction.expandLabel(hkdfAlgortihm, masterSecret, labelIn, hashIn, keyLen);
        } catch (CryptoException e) {
            e.printStackTrace();
            // System.err.println(e.getMessage());
            throw new PreparationException("Could not prepare Key", e);
        }
        msg.getEncryptedSniComputation().setKey(key);
        LOGGER.debug("Key: " + ArrayConverter.bytesToHexString(msg.getEncryptedSniComputation().getKey().getValue()));
    }

    private void prepareIv(EncryptedServerNameIndicationExtensionMessage msg) {
        byte[] iv = null;
        byte[] masterSecret = msg.getEncryptedSniComputation().getMasterSecret().getValue();
        String labelIn = "esni iv";
        byte[] hashIn = msg.getEncryptedSniComputation().getEsniContentsHash().getValue();
        CipherSuite cipherSuite = CipherSuite.TLS_AES_128_GCM_SHA256;
        HKDFAlgorithm hkdfAlgortihm = AlgorithmResolver.getHKDFAlgorithm(cipherSuite);
        int ivLen = 12;
        try {
            iv = HKDFunction.expandLabel(hkdfAlgortihm, masterSecret, labelIn, hashIn, ivLen);
        } catch (CryptoException e) {
            e.printStackTrace();
            // System.err.println(e.getMessage());
            throw new PreparationException("Could not prepare Iv", e);
        }
        msg.getEncryptedSniComputation().setIv(iv);
        LOGGER.debug("Iv: " + ArrayConverter.bytesToHexString(msg.getEncryptedSniComputation().getIv().getValue()));
    }

    private void prepareClientHelloKeyShare(EncryptedServerNameIndicationExtensionMessage msg) {
        ByteArrayOutputStream clientKeyShareStream = new ByteArrayOutputStream();
        ByteArrayOutputStream clientHelloKeyShareStream = new ByteArrayOutputStream();

        for (KeyShareStoreEntry pair : chooser.getClientKeyShares()) {
            KeyShareEntry entry = new KeyShareEntry();
            KeyShareEntrySerializer serializer = new KeyShareEntrySerializer(entry);
            entry.setGroup(pair.getGroup().getValue());
            entry.setPublicKeyLength(pair.getPublicKey().length);
            entry.setPublicKey(pair.getPublicKey());
            try {
                clientKeyShareStream.write(serializer.serialize());
            } catch (IOException e) {
                e.printStackTrace();
                // System.err.println(e.getMessage());
                throw new PreparationException("Failed to write EsniContents", e);
            }
        }
        byte[] keyShareListBytes = clientKeyShareStream.toByteArray();
        int keyShareListBytesLength = keyShareListBytes.length;
        byte[] keyShareListBytesLengthFild = ArrayConverter.intToBytes(keyShareListBytesLength,
                ExtensionByteLength.KEY_SHARE_LIST_LENGTH);
        try {
            clientHelloKeyShareStream.write(keyShareListBytesLengthFild);
            clientHelloKeyShareStream.write(keyShareListBytes);
        } catch (IOException e) {
            e.printStackTrace();
            // System.err.println(e.getMessage());
            throw new PreparationException("Failed to write EsniContents", e);
        }

        byte[] clientHelloKeyShareBytes = clientHelloKeyShareStream.toByteArray();
        msg.getEncryptedSniComputation().setClientHelloKeyShare(clientHelloKeyShareBytes);
        LOGGER.debug("clientHelloKeyShare: "
                + ArrayConverter.bytesToHexString(msg.getEncryptedSniComputation().getClientHelloKeyShare().getValue()));
    }

    private void prepereEncryptedSni(EncryptedServerNameIndicationExtensionMessage msg) {
        byte[] encryptedSni = null;
        byte[] plainText = msg.getClientEsniInnerBytes().getValue();
        byte[] key = msg.getEncryptedSniComputation().getKey().getValue();
        byte[] iv = msg.getEncryptedSniComputation().getIv().getValue();
        byte[] aad = msg.getEncryptedSniComputation().getClientHelloKeyShare().getValue();

        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        GCMParameterSpec pSpec = new GCMParameterSpec(128, iv);
        try {
            Cipher encryptionCipher = Cipher.getInstance("AES/GCM/NoPadding");
            encryptionCipher.init(Cipher.ENCRYPT_MODE, keySpec, pSpec);
            encryptionCipher.updateAAD(aad);
            encryptedSni = encryptionCipher.doFinal(plainText);
        } catch (Exception e) {
            e.printStackTrace();
            // System.err.println(e.getMessage());
            throw new PreparationException("Could not prepare EncryptedSni", e);
        }
        msg.setEncryptedSni(encryptedSni);
        LOGGER.debug("EncryptedSni: " + ArrayConverter.bytesToHexString(msg.getEncryptedSni().getValue()));
    }

    private void prepereEncryptedSniLength(EncryptedServerNameIndicationExtensionMessage msg) {
        msg.setEncryptedSniLength(msg.getEncryptedSni().getValue().length);
        LOGGER.debug("EncryptedSniLength: " + msg.getEncryptedSniLength().getValue());
    }

    private byte[] generateEsniContents(EncryptedServerNameIndicationExtensionMessage msg) {
        ByteArrayOutputStream contentsStream = new ByteArrayOutputStream();
        try {
            contentsStream.write(msg.getRecordDigestLength().getByteArray(ExtensionByteLength.RECORD_DIGEST_LENGTH));
            contentsStream.write(msg.getRecordDigest().getValue());
            contentsStream.write(msg.getKeyShareEntry().getGroup().getValue());
            contentsStream.write(msg.getKeyShareEntry().getPublicKeyLength()
                    .getByteArray(ExtensionByteLength.KEY_SHARE_LENGTH));
            contentsStream.write(msg.getKeyShareEntry().getPublicKey().getValue());
            contentsStream.write(msg.getEncryptedSniComputation().getClientHelloRandom().getValue());
        } catch (IOException e) {
            e.printStackTrace();
            // System.err.println(e.getMessage());
            throw new PreparationException("Failed to generate EsniContents", e);
        }
        return contentsStream.toByteArray();
    }
}