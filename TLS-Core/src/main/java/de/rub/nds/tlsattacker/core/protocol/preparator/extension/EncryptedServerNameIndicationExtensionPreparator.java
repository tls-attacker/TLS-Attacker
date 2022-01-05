/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.Bits;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.DigestAlgorithm;
import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.constants.HKDFAlgorithm;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.crypto.HKDFunction;
import de.rub.nds.tlsattacker.core.crypto.KeyShareCalculator;
import de.rub.nds.tlsattacker.core.crypto.cipher.CipherWrapper;
import de.rub.nds.tlsattacker.core.crypto.cipher.DecryptionCipher;
import de.rub.nds.tlsattacker.core.crypto.cipher.EncryptionCipher;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.exceptions.PreparationException;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ClientEsniInner;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EncryptedServerNameIndicationExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.KeyShareExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareEntry;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareStoreEntry;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.ClientEsniInnerParser;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ClientEsniInnerSerializer;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ExtensionSerializer;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.KeyShareEntrySerializer;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySet;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import de.rub.nds.tlsattacker.core.workflow.chooser.DefaultChooser;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class EncryptedServerNameIndicationExtensionPreparator
    extends ExtensionPreparator<EncryptedServerNameIndicationExtensionMessage> {

    private static final int IV_LENGTH = 12;

    private static final Logger LOGGER = LogManager.getLogger();

    private final EncryptedServerNameIndicationExtensionMessage msg;

    private ClientHelloMessage clientHelloMessage;

    private EsniPreparatorMode esniPreparatorMode;

    public EncryptedServerNameIndicationExtensionPreparator(Chooser chooser,
        EncryptedServerNameIndicationExtensionMessage message,
        ExtensionSerializer<EncryptedServerNameIndicationExtensionMessage> serializer) {
        super(chooser, message, serializer);
        this.msg = message;

        if (chooser.getConnectionEndType() == ConnectionEndType.CLIENT) {
            this.esniPreparatorMode = EsniPreparatorMode.CLIENT;
        } else {
            this.esniPreparatorMode = EsniPreparatorMode.SERVER;
        }
    }

    public ClientHelloMessage getClientHelloMessage() {
        return clientHelloMessage;
    }

    public void setClientHelloMessage(ClientHelloMessage clientHelloMessage) {
        this.clientHelloMessage = clientHelloMessage;
    }

    @Override
    public void prepareExtensionContent() {
        LOGGER.debug("Preparing EncryptedServerNameIndicationExtension");
        switch (this.esniPreparatorMode) {
            case CLIENT:
                configureEsniMessageType(msg);
                prepareClientEsniInner(msg);
                prepareClientEsniInnerBytes(msg);
                prepareCipherSuite(msg);
                prepareNamedGroup(msg);
                prepareKeyShareEntry(msg);
                prepareEsniServerPublicKey(msg);
                prepareEsniRecordBytes(msg);
                prepareRecordDigest(msg);
                prepareRecordDigestLength(msg);
                prepareClientRandom(msg);
                prepareEsniContents(msg);
                prepareEsniContentsHash(msg);
                prepareEsniClientSharedSecret(msg);
                prepareEsniMasterSecret(msg);
                prepareEsniKey(msg);
                prepareEsniIv(msg);
                prepareClientHelloKeyShare(msg);
                prepareEncryptedSni(msg);
                prepareEncryptedSniLength(msg);
                break;
            case SERVER:
                configureEsniMessageType(msg);
                prepareServerNonce(msg);
                break;
            default:
                break;
        }
    }

    @Override
    public void afterPrepareExtensionContent() {
        LOGGER.debug("AfterPreparing EncryptedServerNameIndicationExtension");
        if (this.esniPreparatorMode == EsniPreparatorMode.CLIENT) {
            LOGGER.debug("After preparing EncryptedServerNameIndicationExtension");
            prepareClientRandom(msg);
            prepareEsniContents(msg);
            prepareEsniContentsHash(msg);
            prepareEsniClientSharedSecret(msg);
            prepareEsniMasterSecret(msg);
            prepareEsniKey(msg);
            prepareEsniIv(msg);
            prepareClientHelloKeyShare(msg);
            prepareEncryptedSni(msg);
            prepareEncryptedSniLength(msg);
        }
    }

    public void prepareAfterParse() {
        LOGGER.debug("PreparingAfterParse EncryptedServerNameIndicationExtension");
        if (this.esniPreparatorMode == EsniPreparatorMode.SERVER) {
            try {
                prepareClientRandom(msg);
                prepareEsniContents(msg);
                prepareEsniContentsHash(msg);
                prepareEsniServerSharedSecret(msg);
                prepareEsniMasterSecret(msg);
                prepareEsniKey(msg);
                prepareEsniIv(msg);
                prepareClientHelloKeyShare(msg);
                parseEncryptedSni(msg);
                parseClientEsniInnerBytes(msg);
            } catch (NullPointerException e) {
                throw new PreparationException(
                    "Missing parameters to prepareAfterParse EncryptedServerNameIndicationExtension", e);
            }
        }
    }

    private void configureEsniMessageType(EncryptedServerNameIndicationExtensionMessage msg) {
        if (msg.getEsniMessageTypeConfig() == null) {
            switch (this.esniPreparatorMode) {
                case CLIENT:
                    msg.setEsniMessageTypeConfig(EncryptedServerNameIndicationExtensionMessage.EsniMessageType.CLIENT);
                    break;
                case SERVER:
                    msg.setEsniMessageTypeConfig(EncryptedServerNameIndicationExtensionMessage.EsniMessageType.SERVER);
                    break;
                default:
                    break;
            }
        }
    }

    private void prepareClientEsniInner(EncryptedServerNameIndicationExtensionMessage msg) {
        ClientEsniInnerPreparator clientEsniInnerPreparator =
            new ClientEsniInnerPreparator(this.chooser, msg.getClientEsniInner());
        clientEsniInnerPreparator.prepare();

    }

    private void prepareClientEsniInnerBytes(EncryptedServerNameIndicationExtensionMessage msg) {
        ClientEsniInnerSerializer serializer = new ClientEsniInnerSerializer(msg.getClientEsniInner());
        byte[] clientEsniInnerBytes = serializer.serialize();
        msg.setClientEsniInnerBytes(clientEsniInnerBytes);
        LOGGER.debug(
            "clientEsniInnerBytes: " + ArrayConverter.bytesToHexString(msg.getClientEsniInnerBytes().getValue()));
    }

    private void parseClientEsniInnerBytes(EncryptedServerNameIndicationExtensionMessage msg) {
        ClientEsniInnerParser parser = new ClientEsniInnerParser(0, msg.getClientEsniInnerBytes().getValue());
        ClientEsniInner clientEsniInner = parser.parse();
        msg.setClientEsniInner(clientEsniInner);
    }

    private void prepareEsniServerPublicKey(EncryptedServerNameIndicationExtensionMessage msg) {
        byte[] serverPublicKey = new byte[0];
        for (KeyShareStoreEntry entry : chooser.getEsniServerKeyShareEntries()) {
            if (Arrays.equals(entry.getGroup().getValue(), msg.getKeyShareEntry().getGroup().getValue())) {
                serverPublicKey = entry.getPublicKey();
                break;
            }
        }
        msg.getEncryptedSniComputation().setEsniServerPublicKey(serverPublicKey);
        LOGGER.debug("esniServerPublicKey: "
            + ArrayConverter.bytesToHexString(msg.getEncryptedSniComputation().getEsniServerPublicKey().getValue()));
    }

    private void prepareNamedGroup(EncryptedServerNameIndicationExtensionMessage msg) {
        List<NamedGroup> implementedNamedGroups = NamedGroup.getImplemented();
        List<NamedGroup> clientSupportedNamedGroups = chooser.getConfig().getClientSupportedEsniNamedGroups();
        List<NamedGroup> serverSupportedNamedGroups = new LinkedList();
        for (KeyShareStoreEntry entry : chooser.getEsniServerKeyShareEntries()) {
            serverSupportedNamedGroups.add(entry.getGroup());
        }
        NamedGroup selectedNamedGroup;
        selectedNamedGroup = implementedNamedGroups.get(0);
        boolean isFoundSharedNamedGroup = false;
        for (NamedGroup g : clientSupportedNamedGroups) {
            if (implementedNamedGroups.contains(g)) {
                selectedNamedGroup = g;
                if (serverSupportedNamedGroups.contains(g)) {
                    isFoundSharedNamedGroup = true;
                    break;
                }
            }
        }
        if (!isFoundSharedNamedGroup) {
            LOGGER.warn("Found no shared named group. Using " + selectedNamedGroup);
        }
        msg.getKeyShareEntry().setGroupConfig(selectedNamedGroup);
        LOGGER.debug(
            "NamedGroup: " + ArrayConverter.bytesToHexString(msg.getKeyShareEntry().getGroupConfig().getValue()));

    }

    private void prepareKeyShareEntry(EncryptedServerNameIndicationExtensionMessage msg) {
        KeyShareEntry keyShareEntry = msg.getKeyShareEntry();
        keyShareEntry.setPrivateKey(chooser.getConfig().getDefaultEsniClientPrivateKey());
        KeyShareEntryPreparator keyShareEntryPreparator = new KeyShareEntryPreparator(chooser, keyShareEntry);
        keyShareEntryPreparator.prepare();
        LOGGER.debug("ClientPrivateKey: "
            + ArrayConverter.bytesToHexString(msg.getKeyShareEntry().getPrivateKey().toByteArray()));
        LOGGER.debug(
            "ClientPublicKey: " + ArrayConverter.bytesToHexString(msg.getKeyShareEntry().getPublicKey().getValue()));
    }

    private void prepareCipherSuite(EncryptedServerNameIndicationExtensionMessage msg) {
        List<CipherSuite> clientSupportedCipherSuites = chooser.getConfig().getClientSupportedEsniCipherSuites();
        List<CipherSuite> serverSupportedCipherSuites = ((DefaultChooser) chooser).getEsniServerCipherSuites();
        List<CipherSuite> implementedCipherSuites = CipherSuite.getEsniImplemented();
        CipherSuite selectedCipherSuite = implementedCipherSuites.get(0);
        boolean isFoundSharedCipher = false;
        for (CipherSuite c : clientSupportedCipherSuites) {
            if (implementedCipherSuites.contains(c)) {
                selectedCipherSuite = c;
                if (serverSupportedCipherSuites.contains(c)) {
                    isFoundSharedCipher = true;
                    break;
                }
            }
        }
        if (!isFoundSharedCipher) {
            LOGGER.warn("Found no shared cipher. Using " + selectedCipherSuite);
        }
        msg.setCipherSuite(selectedCipherSuite.getByteValue());
        LOGGER.debug("CipherSuite: " + ArrayConverter.bytesToHexString(msg.getCipherSuite().getValue()));
    }

    private void prepareEsniRecordBytes(EncryptedServerNameIndicationExtensionMessage msg) {
        byte[] recordBytes = chooser.getEsniRecordBytes();
        msg.getEncryptedSniComputation().setEsniRecordBytes(recordBytes);
        LOGGER.debug("esniRecordBytes: "
            + ArrayConverter.bytesToHexString(msg.getEncryptedSniComputation().getEsniRecordBytes()));
    }

    private void prepareRecordDigest(EncryptedServerNameIndicationExtensionMessage msg) {
        byte[] recordDigest;
        byte[] record = msg.getEncryptedSniComputation().getEsniRecordBytes().getValue();
        CipherSuite cipherSuite = CipherSuite.getCipherSuite(msg.getCipherSuite().getValue());
        DigestAlgorithm algorithm = AlgorithmResolver.getDigestAlgorithm(ProtocolVersion.TLS13, cipherSuite);
        if (algorithm == null) {
            LOGGER.warn("Could not select digest algorithm for " + cipherSuite + ". Using SHA256 instead");
            algorithm = DigestAlgorithm.SHA256;
        }
        MessageDigest messageDigest = null;
        try {
            messageDigest = MessageDigest.getInstance(algorithm.getJavaName());
        } catch (NoSuchAlgorithmException e) {
            throw new PreparationException("Could not prepare recordDigest", e);
        }
        recordDigest = messageDigest.digest(record);
        msg.setRecordDigest(recordDigest);
        LOGGER.debug("RecordDigest: " + ArrayConverter.bytesToHexString(msg.getRecordDigest().getValue()));
    }

    private void prepareRecordDigestLength(EncryptedServerNameIndicationExtensionMessage msg) {
        msg.setRecordDigestLength(msg.getRecordDigest().getValue().length);
        LOGGER.debug("RecordDigestLength: " + msg.getRecordDigestLength().getValue());
    }

    private void prepareClientRandom(EncryptedServerNameIndicationExtensionMessage msg) {
        byte[] clientRandom = chooser.getClientRandom();
        if (clientHelloMessage != null) {
            clientRandom = clientHelloMessage.getRandom().getValue();
        } else {
            clientRandom = chooser.getClientRandom();
        }
        msg.getEncryptedSniComputation().setClientHelloRandom(clientRandom);
        LOGGER.debug("ClientHello: " + ArrayConverter.bytesToHexString(clientRandom));
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
        CipherSuite cipherSuite = CipherSuite.getCipherSuite(msg.getCipherSuite().getValue());
        DigestAlgorithm algorithm = AlgorithmResolver.getDigestAlgorithm(ProtocolVersion.TLS13, cipherSuite);
        MessageDigest messageDigest = null;
        try {
            messageDigest = MessageDigest.getInstance(algorithm.getJavaName());
        } catch (NoSuchAlgorithmException e) {
            throw new PreparationException("Could not prepare esniContentsHash", e);
        }
        contentsHash = messageDigest.digest(contents);
        msg.getEncryptedSniComputation().setEsniContentsHash(contentsHash);
        LOGGER.debug("EsniContentsHash: "
            + ArrayConverter.bytesToHexString(msg.getEncryptedSniComputation().getEsniContentsHash().getValue()));
    }

    private void prepareEsniClientSharedSecret(EncryptedServerNameIndicationExtensionMessage msg) {
        NamedGroup group = NamedGroup.getNamedGroup(msg.getKeyShareEntry().getGroup().getValue());
        BigInteger clientPrivateKey = msg.getKeyShareEntry().getPrivateKey();
        byte[] serverPublicKey = msg.getEncryptedSniComputation().getEsniServerPublicKey().getValue();
        byte[] esniSharedSecret = KeyShareCalculator.computeSharedSecret(group, clientPrivateKey, serverPublicKey);
        msg.getEncryptedSniComputation().setEsniSharedSecret(esniSharedSecret);
        LOGGER.debug("esniSharedSecret: "
            + ArrayConverter.bytesToHexString(msg.getEncryptedSniComputation().getEsniSharedSecret().getValue()));
    }

    private void prepareEsniServerSharedSecret(EncryptedServerNameIndicationExtensionMessage msg) {
        NamedGroup group = NamedGroup.getNamedGroup(msg.getKeyShareEntry().getGroup().getValue());
        boolean isFoundSharedNamedGroup = false;
        BigInteger serverPrivateKey = chooser.getConfig().getEsniServerKeyPairs().get(0).getPrivateKey();
        for (KeyShareEntry keyShareEntry : chooser.getConfig().getEsniServerKeyPairs()) {
            if (Arrays.equals(keyShareEntry.getGroup().getValue(), group.getValue())) {
                serverPrivateKey = keyShareEntry.getPrivateKey();
                isFoundSharedNamedGroup = true;
                break;
            }
        }
        if (!isFoundSharedNamedGroup) {
            LOGGER.warn("No private key available for selected named group: " + group);
        }
        byte[] clientPublicKey = msg.getKeyShareEntry().getPublicKey().getValue();
        ;
        byte[] esniSharedSecret = KeyShareCalculator.computeSharedSecret(group, serverPrivateKey, clientPublicKey);

        msg.getEncryptedSniComputation().setEsniSharedSecret(esniSharedSecret);
        LOGGER.debug("esniSharedSecret: "
            + ArrayConverter.bytesToHexString(msg.getEncryptedSniComputation().getEsniSharedSecret().getValue()));
    }

    private void prepareEsniMasterSecret(EncryptedServerNameIndicationExtensionMessage msg) {
        byte[] esniMasterSecret = null;
        byte[] esniSharedSecret = msg.getEncryptedSniComputation().getEsniSharedSecret().getValue();
        CipherSuite cipherSuite = CipherSuite.getCipherSuite(msg.getCipherSuite().getValue());
        HKDFAlgorithm hkdfAlgorithm = AlgorithmResolver.getHKDFAlgorithm(cipherSuite);
        try {
            esniMasterSecret = HKDFunction.extract(hkdfAlgorithm, null, esniSharedSecret);
        } catch (CryptoException e) {
            throw new PreparationException("Could not prepare esniMasterSecret", e);
        }
        msg.getEncryptedSniComputation().setEsniMasterSecret(esniMasterSecret);
        LOGGER.debug("esniMasterSecret: "
            + ArrayConverter.bytesToHexString(msg.getEncryptedSniComputation().getEsniMasterSecret().getValue()));
    }

    private void prepareEsniKey(EncryptedServerNameIndicationExtensionMessage msg) {

        byte[] key = null;
        byte[] esniMasterSecret = msg.getEncryptedSniComputation().getEsniMasterSecret().getValue();
        byte[] hashIn = msg.getEncryptedSniComputation().getEsniContentsHash().getValue();
        CipherSuite cipherSuite = CipherSuite.getCipherSuite(msg.getCipherSuite().getValue());
        HKDFAlgorithm hkdfAlgorithm = AlgorithmResolver.getHKDFAlgorithm(cipherSuite);
        int keyLen = AlgorithmResolver.getCipher(cipherSuite).getKeySize();
        try {
            key = HKDFunction.expandLabel(hkdfAlgorithm, esniMasterSecret, HKDFunction.ESNI_KEY, hashIn, keyLen);
        } catch (CryptoException e) {
            throw new PreparationException("Could not prepare esniKey", e);
        }
        msg.getEncryptedSniComputation().setEsniKey(key);
        LOGGER.debug(
            "esniKey: " + ArrayConverter.bytesToHexString(msg.getEncryptedSniComputation().getEsniKey().getValue()));
    }

    private void prepareEsniIv(EncryptedServerNameIndicationExtensionMessage msg) {
        byte[] iv = null;
        byte[] esniMasterSecret = msg.getEncryptedSniComputation().getEsniMasterSecret().getValue();
        byte[] hashIn = msg.getEncryptedSniComputation().getEsniContentsHash().getValue();
        CipherSuite cipherSuite = CipherSuite.getCipherSuite(msg.getCipherSuite().getValue());
        HKDFAlgorithm hkdfAlgorithm = AlgorithmResolver.getHKDFAlgorithm(cipherSuite);
        try {
            iv = HKDFunction.expandLabel(hkdfAlgorithm, esniMasterSecret, HKDFunction.ESNI_IV, hashIn, IV_LENGTH);
        } catch (CryptoException e) {
            throw new PreparationException("Could not prepare esniIv", e);
        }
        msg.getEncryptedSniComputation().setEsniIv(iv);
        LOGGER.debug(
            "esniIv: " + ArrayConverter.bytesToHexString(msg.getEncryptedSniComputation().getEsniIv().getValue()));
    }

    private void prepareClientHelloKeyShare(EncryptedServerNameIndicationExtensionMessage msg) {
        int keyShareListBytesLength = 0;
        byte[] keyShareListBytesLengthField = null;
        byte[] keyShareListBytes = null;
        ByteArrayOutputStream clientHelloKeyShareStream = new ByteArrayOutputStream();
        boolean isClientHelloExtensionsFound = false;
        if (clientHelloMessage != null) {

            List<ExtensionMessage> clientHelloExtensions = clientHelloMessage.getExtensions();
            for (ExtensionMessage m : clientHelloExtensions) {
                if (m instanceof KeyShareExtensionMessage) {
                    KeyShareExtensionMessage keyShareExtensionMessage = (KeyShareExtensionMessage) m;
                    keyShareListBytesLength = keyShareExtensionMessage.getKeyShareListLength().getValue();
                    keyShareListBytes = keyShareExtensionMessage.getKeyShareListBytes().getValue();
                    isClientHelloExtensionsFound = true;
                    break;
                }
            }
        }
        if (!isClientHelloExtensionsFound) {
            ByteArrayOutputStream keyShareListStream = new ByteArrayOutputStream();
            for (KeyShareStoreEntry pair : chooser.getClientKeyShares()) {
                KeyShareEntry entry = new KeyShareEntry();
                KeyShareEntrySerializer serializer = new KeyShareEntrySerializer(entry);
                entry.setGroup(pair.getGroup().getValue());
                entry.setPublicKeyLength(pair.getPublicKey().length);
                entry.setPublicKey(pair.getPublicKey());
                try {
                    keyShareListStream.write(serializer.serialize());
                } catch (IOException e) {
                    throw new PreparationException("Failed to write esniContents", e);
                }
            }
            keyShareListBytes = keyShareListStream.toByteArray();
            keyShareListBytesLength = keyShareListBytes.length;
        }

        keyShareListBytesLengthField =
            ArrayConverter.intToBytes(keyShareListBytesLength, ExtensionByteLength.KEY_SHARE_LIST_LENGTH);
        try {
            clientHelloKeyShareStream.write(keyShareListBytesLengthField);
            clientHelloKeyShareStream.write(keyShareListBytes);
        } catch (IOException e) {
            throw new PreparationException("Failed to write ClientHelloKeyShare", e);
        }
        byte[] clientHelloKeyShareBytes = clientHelloKeyShareStream.toByteArray();
        msg.getEncryptedSniComputation().setClientHelloKeyShare(clientHelloKeyShareBytes);
        LOGGER.debug("clientHelloKeyShare: " + ArrayConverter.bytesToHexString(clientHelloKeyShareBytes));
    }

    private void prepareEncryptedSni(EncryptedServerNameIndicationExtensionMessage msg) {
        byte[] encryptedSni = null;

        CipherSuite cipherSuite = CipherSuite.getCipherSuite(msg.getCipherSuite().getValue());
        byte[] plainText = msg.getClientEsniInnerBytes().getValue();
        byte[] key = msg.getEncryptedSniComputation().getEsniKey().getValue();
        byte[] iv = msg.getEncryptedSniComputation().getEsniIv().getValue();
        byte[] aad = msg.getEncryptedSniComputation().getClientHelloKeyShare().getValue();
        int tagBitLength;
        if (cipherSuite.isCCM_8()) {
            tagBitLength = 8 * Bits.IN_A_BYTE;
        } else {
            tagBitLength = 16 * Bits.IN_A_BYTE;
        }
        KeySet keySet = new KeySet();
        keySet.setClientWriteKey(key);
        EncryptionCipher encryptCipher =
            CipherWrapper.getEncryptionCipher(cipherSuite, ConnectionEndType.CLIENT, keySet);
        try {
            encryptedSni = encryptCipher.encrypt(iv, tagBitLength, aad, plainText);
        } catch (CryptoException e) {
            throw new PreparationException("Could not encrypt clientEsniInnerBytes", e);
        }

        msg.setEncryptedSni(encryptedSni);
        LOGGER.debug("EncryptedSni: " + ArrayConverter.bytesToHexString(msg.getEncryptedSni().getValue()));
    }

    private void parseEncryptedSni(EncryptedServerNameIndicationExtensionMessage msg) {
        byte[] clientEsniInnerBytes = null;

        CipherSuite cipherSuite = CipherSuite.getCipherSuite(msg.getCipherSuite().getValue());
        byte[] cipherText = msg.getEncryptedSni().getValue();
        byte[] key = msg.getEncryptedSniComputation().getEsniKey().getValue();
        byte[] iv = msg.getEncryptedSniComputation().getEsniIv().getValue();
        byte[] aad = msg.getEncryptedSniComputation().getClientHelloKeyShare().getValue();
        int tagBitLength;
        if (cipherSuite.isCCM_8()) {
            tagBitLength = 8 * Bits.IN_A_BYTE;
        } else {
            tagBitLength = 16 * Bits.IN_A_BYTE;
        }
        KeySet keySet = new KeySet();
        keySet.setClientWriteKey(key);

        DecryptionCipher decryptCipher =
            CipherWrapper.getDecryptionCipher(cipherSuite, ConnectionEndType.SERVER, keySet);
        try {
            clientEsniInnerBytes = decryptCipher.decrypt(iv, tagBitLength, aad, cipherText);
        } catch (CryptoException e) {
            throw new PreparationException("Could not decrypt encryptedSni", e);
        }

        msg.setClientEsniInnerBytes(clientEsniInnerBytes);
        LOGGER.debug(
            "ClientESNIInnerBytes: " + ArrayConverter.bytesToHexString(msg.getClientEsniInnerBytes().getValue()));
    }

    private void prepareEncryptedSniLength(EncryptedServerNameIndicationExtensionMessage msg) {
        msg.setEncryptedSniLength(msg.getEncryptedSni().getValue().length);
        LOGGER.debug("EncryptedSniLength: " + msg.getEncryptedSniLength().getValue());
    }

    private void prepareServerNonce(EncryptedServerNameIndicationExtensionMessage msg) {
        byte[] receivedClientNonce = chooser.getEsniClientNonce();
        msg.setServerNonce(receivedClientNonce);
        LOGGER.debug("ServerNonce: " + ArrayConverter.bytesToHexString(msg.getServerNonce().getValue()));
    }

    private byte[] generateEsniContents(EncryptedServerNameIndicationExtensionMessage msg) {
        ByteArrayOutputStream contentsStream = new ByteArrayOutputStream();
        try {
            contentsStream.write(msg.getRecordDigestLength().getByteArray(ExtensionByteLength.RECORD_DIGEST_LENGTH));
            contentsStream.write(msg.getRecordDigest().getValue());
            contentsStream.write(msg.getKeyShareEntry().getGroup().getValue());
            contentsStream
                .write(msg.getKeyShareEntry().getPublicKeyLength().getByteArray(ExtensionByteLength.KEY_SHARE_LENGTH));
            contentsStream.write(msg.getKeyShareEntry().getPublicKey().getValue());
            contentsStream.write(msg.getEncryptedSniComputation().getClientHelloRandom().getValue());
        } catch (IOException e) {
            throw new PreparationException("Failed to generate esniContents", e);
        }
        return contentsStream.toByteArray();
    }

    public EsniPreparatorMode getEsniPreparatorMode() {
        return esniPreparatorMode;
    }

    public void setEsniPreparatorMode(EsniPreparatorMode esniPreparatorMode) {
        this.esniPreparatorMode = esniPreparatorMode;
    }

    public enum EsniPreparatorMode {
        CLIENT,
        SERVER;
    }

}
