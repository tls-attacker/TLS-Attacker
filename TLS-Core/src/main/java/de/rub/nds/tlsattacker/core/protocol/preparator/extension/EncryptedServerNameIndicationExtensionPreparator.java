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
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.tls.TlsUtils;

//import org.bouncycastle.crypto.tls.HashAlgorithm;
//import de.rub.nds.tlsattacker.core.constants.HashAlgorithm;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.DigestAlgorithm;
import de.rub.nds.tlsattacker.core.constants.HKDFAlgorithm;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.crypto.HKDFunction;
import de.rub.nds.tlsattacker.core.crypto.ec.ForgivingX25519Curve;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.exceptions.PreparationException;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EncryptedServerNameIndicationExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.esni.ClientEsniInnerPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ExtensionSerializer;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.esni.ClientEsniInnerSerializer;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

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
        LOGGER.warn("EncryptedServerNameIndicationExtensionPreparator called. - ESNI implemented yet");
    }

    @Override
    public void prepareExtensionContent() {
        LOGGER.debug("Preparing EncryptedServerNameIndicationExtension");
        prepareClientEsniInner(msg);
        prepareClientEsniInnerBytes(msg);

        // prepareRecordBytese(msg);
        // prepareSke(msg);
        // preparePk(msg);

        prepareCipherSuitee(msg);
        prepareGroupName(msg);
        // prepareKeyShareEntry(msg);
        prepareKeyShareEntryLength(msg);

        prepareRecordDigest(msg);
        prepareRecordDigestLength(msg);

        prepareEsniContents(msg);
        prepareEsniContentsHash(msg);
        prepareSharedSecret(msg);
        prepareMasterSecret(msg);
        prepareKey(msg);
        prepareIv(msg);
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
        LOGGER.debug("streamClientEsniInnerBytes: "
                + ArrayConverter.bytesToHexString(msg.getClientEsniInnerBytes().getValue()));
    }

    private void preparePk(EncryptedServerNameIndicationExtensionMessage msg) {
        // TODO: Read form DNS KeyRecord
        // byte[] pk = null;
        // msg.getEncryptedSniComputation().setPk(pk);
        // LOGGER.debug("Pk: " +
        // ArrayConverter.bytesToHexString(msg.getEncryptedSniComputation().getPk().getValue()));
    }

    private void prepareCipherSuitee(EncryptedServerNameIndicationExtensionMessage msg) {
        msg.setCipherSuite(msg.getCipherSuiteConfig());
    }

    private void prepareGroupName(EncryptedServerNameIndicationExtensionMessage msg) {
        byte[] group = msg.getKeyShareEntry().getNamedGroup().getValue();
        if (!Arrays.equals(group, new byte[] { (byte) 0x00, (byte) 0x1d })) {
            LOGGER.error("NamedGroup not supported. Only DHEC Curve X25519 is supportet yet.");
            throw new PreparationException("NamedGroup not supported yet.");
        }
        msg.getEncryptedSniComputation().setNamedGroup(group);
        LOGGER.debug("NamedGroup: "
                + ArrayConverter.bytesToHexString(msg.getEncryptedSniComputation().getNamedGroup().getValue()));
    }

    private void prepareKeyShareEntryLength(EncryptedServerNameIndicationExtensionMessage msg) {
        int keyExchangeLength = msg.getKeyShareEntry().getKeyExchange().getValue().length;
        msg.getKeyShareEntry().setKeyExchangeLength(keyExchangeLength);
        LOGGER.debug("KeyExchangeLength: " + msg.getKeyShareEntry().getKeyExchangeLength().getValue());
    }

    private void prepareKeyShareEntry(EncryptedServerNameIndicationExtensionMessage msg) {
        // TODO Create pk from sk and put pk in KeyShareEntry
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
        byte[] sk = msg.getEncryptedSniComputation().getSk().getValue();
        byte[] pk = msg.getEncryptedSniComputation().getPk().getValue();
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
            contentsStream.write(msg.getRecordDigestLength().getByteArray(2));
            contentsStream.write(msg.getRecordDigest().getValue());
            contentsStream.write(msg.getKeyShareEntry().getNamedGroup().getValue());
            contentsStream.write(msg.getKeyShareEntry().getKeyExchangeLength().getByteArray(2));
            contentsStream.write(msg.getKeyShareEntry().getKeyExchange().getValue());
            contentsStream.write(msg.getEncryptedSniComputation().getClientHelloRandom().getValue());
        } catch (IOException e) {
            e.printStackTrace();
            // System.err.println(e.getMessage());
            throw new PreparationException("Failed to generate EsniContents", e);
        }
        return contentsStream.toByteArray();

    }
}