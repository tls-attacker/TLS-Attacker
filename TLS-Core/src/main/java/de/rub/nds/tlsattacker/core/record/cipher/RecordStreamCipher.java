/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.record.cipher;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.Tls13KeySetType;
import de.rub.nds.tlsattacker.core.crypto.cipher.CipherWrapper;
import de.rub.nds.tlsattacker.core.crypto.mac.MacWrapper;
import de.rub.nds.tlsattacker.core.crypto.mac.WrappedMac;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.DecryptionRequest;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.DecryptionResult;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.EncryptionRequest;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.EncryptionResult;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySet;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class RecordStreamCipher extends RecordCipher {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * mac for verification of incoming messages
     */
    private WrappedMac readMac;
    /**
     * mac object for macing outgoing messages
     */
    private WrappedMac writeMac;

    public RecordStreamCipher(TlsContext context, KeySet keySet) {
        super(context, keySet);
        initCipherAndMac();
    }

    private void initCipherAndMac() throws UnsupportedOperationException {
        try {
            ConnectionEndType localConEndType = context.getConnection().getLocalConnectionEndType();
            encryptCipher = CipherWrapper.getEncryptionCipher(cipherSuite, localConEndType, getKeySet());
            decryptCipher = CipherWrapper.getDecryptionCipher(cipherSuite, localConEndType, getKeySet());
            readMac = MacWrapper.getMac(version, cipherSuite, getKeySet().getReadMacSecret(localConEndType));
            writeMac = MacWrapper.getMac(version, cipherSuite, getKeySet().getWriteMacSecret(localConEndType));
        } catch (NoSuchAlgorithmException ex) {
            throw new UnsupportedOperationException("Cipher not supported: " + cipherSuite.name(), ex);
        }
    }

    @Override
    public EncryptionResult encrypt(EncryptionRequest request) {
        try {
            return new EncryptionResult(encryptCipher.encrypt(request.getPlainText()));
        } catch (CryptoException E) {
            LOGGER.warn("Could not encrypt Data with the provided parameters. Returning unencrypted data.");
            LOGGER.debug(E);
            return new EncryptionResult(request.getPlainText());
        }
    }

    @Override
    public DecryptionResult decrypt(DecryptionRequest decryptionRequest) {
        try {
            return new DecryptionResult(null, decryptCipher.decrypt(decryptionRequest.getCipherText()), null, true);
        } catch (CryptoException E) {
            LOGGER.warn("Could not decrypt Data with the provided parameters. Returning undecrypted data.");
            LOGGER.debug(E);
            return new DecryptionResult(null, decryptionRequest.getCipherText(), false, false);
        }
    }

    @Override
    public int getMacLength() {
        return readMac.getMacLength();
    }

    @Override
    public byte[] calculateMac(byte[] data, ConnectionEndType connectionEndType) {
        LOGGER.debug("The MAC was calculated over the following data: {}", ArrayConverter.bytesToHexString(data));
        byte[] result;
        if (connectionEndType == context.getChooser().getConnectionEndType()) {
            result = writeMac.calculateMac(data);
        } else {
            result = readMac.calculateMac(data);
        }
        LOGGER.debug("MAC: {}", ArrayConverter.bytesToHexString(result));
        return result;
    }

    @Override
    public byte[] calculatePadding(int paddingLength) {
        return new byte[0];
    }

    @Override
    public int calculatePaddingLength(int dataLength) {
        return 0;
    }

    @Override
    public boolean isUsingPadding() {
        return false;
    }

    @Override
    public boolean isUsingMac() {
        return true;
    }

    @Override
    public boolean isUsingTags() {
        return false;
    }

    @Override
    public byte[] getEncryptionIV() {
        return new byte[0];
    }

    @Override
    public byte[] getDecryptionIV() {
        return new byte[0];
    }

    @Override
    public void encrypt(Record record) {

        LOGGER.debug("Encrypting Record:");
        CipherSuite cipherSuite = context.getChooser().getSelectedCipherSuite();
        // initialising mac
        record.getComputations().setMac(new byte[0]);
        byte[] cleanBytes = record.getCleanProtocolMessageBytes().getValue();

        record.getComputations().setNonMetaDataMaced(cleanBytes);
        if (context.getChooser().getSelectedProtocolVersion().isTLS13()) {
            // TLS13 needs the record length before encrypting
            // Encrypted length
            int cleanLength = record.getCleanProtocolMessageBytes().getValue().length;
            int length = cleanLength + recordCipher.getTagSize() + 1; // +1 for
            // the
            // encrypted
            // record
            // type
            record.setLength(length);
        }
        byte[] additionalAuthenticatedData = collectAdditionalAuthenticatedData(record, context.getChooser()
                .getSelectedProtocolVersion());
        record.getComputations().setAuthenticatedMetaData(additionalAuthenticatedData);
        if (!isEncryptThenMac(cipherSuite) && cipherSuite.isUsingMac()) {
            LOGGER.debug("EncryptThenMac Extension is not active");

            byte[] mac = recordCipher.calculateMac(ArrayConverter.concatenate(record.getComputations()
                    .getAuthenticatedMetaData().getValue(), record.getComputations().getAuthenticatedNonMetaData()
                            .getValue()), context.getChooser().getConnectionEndType());
            setMac(record, mac);
        }

        setUnpaddedRecordBytes(record, cleanBytes);

        byte[] padding;

        if (context.getChooser().getSelectedProtocolVersion().isTLS13()
                || context.getActiveKeySetTypeWrite() == Tls13KeySetType.EARLY_TRAFFIC_SECRETS) {
            padding = recordCipher.calculatePadding(record.getComputations().getAdditionalPaddingLength().getValue());
        } else {
            int paddingLength = recordCipher.calculatePaddingLength(record.getComputations().getUnpaddedRecordBytes()
                    .getValue().length);
            record.getComputations().setPaddingLength(paddingLength);
            padding = recordCipher.calculatePadding(record.getComputations().getAdditionalPaddingLength().getValue());
        }
        setPadding(record, padding);
        setPaddingLength(record);
        byte[] plain;
        if ((context.getChooser().getSelectedProtocolVersion().isTLS13() || context.getActiveKeySetTypeWrite() == Tls13KeySetType.EARLY_TRAFFIC_SECRETS)
                && context.getActiveKeySetTypeWrite() != Tls13KeySetType.NONE) {
            plain = ArrayConverter.concatenate(record.getComputations().getUnpaddedRecordBytes().getValue(), record
                    .getContentMessageType().getArrayValue(), record.getComputations().getPadding().getValue());
        } else {
            plain = ArrayConverter.concatenate(record.getComputations().getUnpaddedRecordBytes().getValue(), record
                    .getComputations().getPadding().getValue());
        }
        setPlainRecordBytes(record, plain);
        byte[] encrypted = recordCipher.encrypt(
                getEncryptionRequest(record.getComputations().getPlainRecordBytes().getValue(), record
                        .getComputations().getAuthenticatedMetaData().getValue())).getCompleteEncryptedCipherText();
        if (isEncryptThenMac(cipherSuite)) {
            LOGGER.debug("EncryptThenMac Extension active");
            record.getComputations().setNonMetaDataMaced(encrypted);
            additionalAuthenticatedData = collectAdditionalAuthenticatedData(record, context.getChooser()
                    .getSelectedProtocolVersion());
            record.getComputations().setAuthenticatedMetaData(additionalAuthenticatedData);
            byte[] mac = recordCipher.calculateMac(ArrayConverter.concatenate(record.getComputations()
                    .getAuthenticatedMetaData().getValue(), encrypted), context.getChooser().getConnectionEndType());
            setMac(record, mac);
            encrypted = ArrayConverter.concatenate(encrypted, record.getComputations().getMac().getValue());
        }
        setProtocolMessageBytes(record, encrypted);
        context.increaseWriteSequenceNumber();
    }

    @Override
    public void decrypt(Record record) {
        LOGGER.debug("Decrypting Record");
        record.prepareComputations();
        if (recordCipher.getKeySet() != null) {
            record.getComputations().setMacKey(
                    recordCipher.getKeySet().getReadMacSecret(context.getChooser().getConnectionEndType()));
            record.getComputations().setCipherKey(
                    recordCipher.getKeySet().getReadKey(context.getChooser().getConnectionEndType()));
        }
        record.getComputations().setSequenceNumber(BigInteger.valueOf(context.getReadSequenceNumber()));
        byte[] encrypted = record.getProtocolMessageBytes().getValue();
        CipherSuite cipherSuite = context.getChooser().getSelectedCipherSuite();
        prepareNonMetaDataMaced(record, encrypted);
        prepareAdditionalMetadata(record);
        if (isEncryptThenMac(cipherSuite)) {
            LOGGER.trace("EncryptThenMac is active");
            byte[] mac = parseMac(record.getProtocolMessageBytes().getValue());
            record.getComputations().setMac(mac);
            encrypted = removeMac(record.getProtocolMessageBytes().getValue());
        }
        LOGGER.debug("Decrypting:" + ArrayConverter.bytesToHexString(encrypted));
        DecryptionResult result = recordCipher.decrypt(new DecryptionRequest(record.getComputations()
                .getAuthenticatedMetaData().getValue(), encrypted));
        byte[] decrypted = result.getDecryptedCipherText();
        record.getComputations().setPlainRecordBytes(decrypted);
        record.getComputations().setInitialisationVector(result.getInitialisationVector());
        LOGGER.debug("PlainRecordBytes: "
                + ArrayConverter.bytesToHexString(record.getComputations().getPlainRecordBytes().getValue()));
        if (recordCipher.isUsingPadding() && result.isSuccessful()) {
            if (!context.getChooser().getSelectedProtocolVersion().isTLS13()
                    && context.getActiveKeySetTypeRead() != Tls13KeySetType.EARLY_TRAFFIC_SECRETS) {
                adjustPaddingTLS(record);
            } else {
                adjustPaddingTLS13(record);
            }
        } else {
            useNoPadding(record);
        }
        if (!isEncryptThenMac(cipherSuite) && recordCipher.isUsingMac() && result.isSuccessful()) {
            LOGGER.trace("EncryptThenMac is not active");
            if (cipherSuite.isUsingMac()) {
                adjustMac(record);
            } else {
                useNoMac(record);
            }
            prepareNonMetaDataMaced(record, record.getCleanProtocolMessageBytes().getValue());
            prepareAdditionalMetadata(record);

        } else {
            useNoMac(record);
        }
        context.increaseReadSequenceNumber();
        if (context.getChooser().getConnectionEndType() == ConnectionEndType.SERVER
                && context.getActiveClientKeySetType() == Tls13KeySetType.EARLY_TRAFFIC_SECRETS) {
            checkForEndOfEarlyData(record.getComputations().getUnpaddedRecordBytes().getValue());
        }
        if (result.isSuccessful()) {
            record.getComputations().setPaddingValid(isPaddingValid(record));
            record.getComputations().setMacValid(isMacValid(record));
        }
    }
}
