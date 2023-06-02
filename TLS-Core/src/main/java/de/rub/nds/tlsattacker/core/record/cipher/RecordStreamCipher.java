/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.record.cipher;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.crypto.cipher.CipherWrapper;
import de.rub.nds.tlsattacker.core.crypto.mac.MacWrapper;
import de.rub.nds.tlsattacker.core.crypto.mac.WrappedMac;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.layer.data.Parser;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.record.RecordCryptoComputations;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.io.ByteArrayInputStream;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class RecordStreamCipher extends RecordCipher {

    private static final Logger LOGGER = LogManager.getLogger();

    /** mac for verification of incoming messages */
    private WrappedMac readMac;
    /** mac object for macing outgoing messages */
    private WrappedMac writeMac;

    public RecordStreamCipher(TlsContext tlsContext, CipherState state) {
        super(tlsContext, state);
        initCipherAndMac();
    }

    private void initCipherAndMac() throws UnsupportedOperationException {
        try {
            encryptCipher =
                    CipherWrapper.getEncryptionCipher(
                            getState().getCipherSuite(),
                            getLocalConnectionEndType(),
                            getState().getKeySet());
            decryptCipher =
                    CipherWrapper.getDecryptionCipher(
                            getState().getCipherSuite(),
                            getLocalConnectionEndType(),
                            getState().getKeySet());
            readMac =
                    MacWrapper.getMac(
                            getState().getVersion(),
                            getState().getCipherSuite(),
                            getState().getKeySet().getReadMacSecret(getLocalConnectionEndType()));
            writeMac =
                    MacWrapper.getMac(
                            getState().getVersion(),
                            getState().getCipherSuite(),
                            getState().getKeySet().getWriteMacSecret(getLocalConnectionEndType()));
        } catch (NoSuchAlgorithmException ex) {
            throw new UnsupportedOperationException(
                    "Cipher not supported: " + getState().getCipherSuite().name(), ex);
        }
    }

    public byte[] calculateMac(byte[] data, ConnectionEndType connectionEndType) {
        LOGGER.debug("The MAC was calculated over the following data: {}", data);
        byte[] result;
        if (connectionEndType == getConnectionEndType()) {
            result = writeMac.calculateMac(data);
        } else {
            result = readMac.calculateMac(data);
        }
        LOGGER.debug("MAC: {}", result);
        return result;
    }

    @Override
    public void encrypt(Record record) throws CryptoException {
        if (record.getComputations() == null) {
            LOGGER.warn("Record computations are not prepared.");
            record.prepareComputations();
        }
        LOGGER.debug("Encrypting Record:");
        RecordCryptoComputations computations = record.getComputations();
        computations.setMacKey(getState().getKeySet().getWriteMacSecret(getConnectionEndType()));
        computations.setCipherKey(getState().getKeySet().getWriteKey(getConnectionEndType()));

        byte[] cleanBytes = record.getCleanProtocolMessageBytes().getValue();

        computations.setAuthenticatedNonMetaData(cleanBytes);

        // For unusual handshakes we need the length here if TLS 1.3 is
        // negotiated as a version.
        record.setLength(
                cleanBytes.length
                        + AlgorithmResolver.getMacAlgorithm(
                                        getState().getVersion(), getState().getCipherSuite())
                                .getSize());

        computations.setAuthenticatedMetaData(
                collectAdditionalAuthenticatedData(record, getState().getVersion()));
        computations.setMac(
                calculateMac(
                        ArrayConverter.concatenate(
                                computations.getAuthenticatedMetaData().getValue(),
                                computations.getAuthenticatedNonMetaData().getValue()),
                        getLocalConnectionEndType()));

        computations.setPlainRecordBytes(
                ArrayConverter.concatenate(
                        record.getCleanProtocolMessageBytes().getValue(),
                        computations.getMac().getValue()));

        computations.setCiphertext(
                encryptCipher.encrypt(record.getComputations().getPlainRecordBytes().getValue()));

        record.setProtocolMessageBytes(computations.getCiphertext().getValue());
        // TODO our macs are always valid
        computations.setMacValid(true);
    }

    @Override
    public void decrypt(Record record) throws CryptoException {
        if (record.getComputations() == null) {
            LOGGER.warn("Record computations are not prepared.");
            record.prepareComputations();
        }
        LOGGER.debug("Decrypting Record");
        RecordCryptoComputations computations = record.getComputations();

        computations.setMacKey(getState().getKeySet().getReadMacSecret(getConnectionEndType()));
        computations.setCipherKey(getState().getKeySet().getReadKey(getConnectionEndType()));

        byte[] cipherText = record.getProtocolMessageBytes().getValue();

        computations.setCiphertext(cipherText);
        byte[] plainData = decryptCipher.decrypt(cipherText);
        computations.setPlainRecordBytes(plainData);
        plainData = computations.getPlainRecordBytes().getValue();
        PlaintextParser parser = new PlaintextParser(plainData);
        byte[] cleanBytes = parser.parseByteArrayField(plainData.length - readMac.getMacLength());
        record.setCleanProtocolMessageBytes(cleanBytes);
        record.getComputations().setAuthenticatedNonMetaData(cleanBytes);
        record.getComputations()
                .setAuthenticatedMetaData(
                        collectAdditionalAuthenticatedData(record, getState().getVersion()));
        byte[] hmac = parser.parseByteArrayField(readMac.getMacLength());
        record.getComputations().setMac(hmac);
        byte[] calculatedHmac =
                calculateMac(
                        ArrayConverter.concatenate(
                                record.getComputations().getAuthenticatedMetaData().getValue(),
                                record.getComputations().getAuthenticatedNonMetaData().getValue()),
                        getTalkingConnectionEndType());
        record.getComputations().setMacValid(Arrays.equals(hmac, calculatedHmac));
    }

    class PlaintextParser extends Parser<Object> {

        public PlaintextParser(byte[] array) {
            super(new ByteArrayInputStream(array));
        }

        @Override
        public byte[] parseByteArrayField(int length) {
            return super.parseByteArrayField(length);
        }

        @Override
        public int getBytesLeft() {
            return super.getBytesLeft();
        }

        @Override
        public void parse(Object t) {
            throw new UnsupportedOperationException(
                    "Not supported yet."); // To change body of generated methods,
            // choose Tools | Templates.
        }
    }
}
