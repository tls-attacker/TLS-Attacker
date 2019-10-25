/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.record.crypto;

import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.Tls13KeySetType;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.record.BlobRecord;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipher;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipherFactory;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.DecryptionRequest;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.DecryptionResult;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySet;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySetGenerator;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class RecordDecryptor extends Decryptor {

    private static final Logger LOGGER = LogManager.getLogger();

    private final TlsContext context;

    public RecordDecryptor(RecordCipher recordCipher, TlsContext context) {
        super(recordCipher);
        this.context = context;
    }

    @Override
    public void decrypt(BlobRecord record) {
        LOGGER.debug("Decrypting BlobRecord");
        DecryptionResult result = recordCipher.decrypt(new DecryptionRequest(null, record.getProtocolMessageBytes()
                .getValue()));
        byte[] decrypted = result.getDecryptedCipherText();
        record.setCleanProtocolMessageBytes(decrypted);
        LOGGER.debug("CleanProtocolMessageBytes: "
                + ArrayConverter.bytesToHexString(record.getCleanProtocolMessageBytes().getValue()));
    }

    @Override
    public void decrypt(Record record) throws CryptoException {
        LOGGER.debug("Decrypting Record");
        record.prepareComputations();
        if (recordCipher.getKeySet() != null) {
            record.getComputations().setMacKey(
                    recordCipher.getKeySet().getReadMacSecret(context.getChooser().getConnectionEndType()));
            record.getComputations().setCipherKey(
                    recordCipher.getKeySet().getReadKey(context.getChooser().getConnectionEndType()));
        }
        if (context.getChooser().getSelectedProtocolVersion().isDTLS()) {
            record.getComputations().setSequenceNumber(record.getSequenceNumber().getValue());
        } else {
            record.getComputations().setSequenceNumber(BigInteger.valueOf(context.getReadSequenceNumber()));
        }
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

    private Boolean isPaddingValid(Record record) {
        ModifiableByteArray padding = record.getComputations().getPadding();
        if (padding != null && padding.getValue() != null && padding.getValue().length > 0) {
            if (context.getChooser().getSelectedProtocolVersion().isSSL()) {
                return true;
            }
            for (int i = 0; i < padding.getValue().length; i++) {
                if (padding.getValue()[i] != padding.getValue().length - 1) {
                    LOGGER.debug("Padding is invalid");
                    return false;
                }
            }
            LOGGER.debug("Padding is valid");
            return true;
        } else {
            return null;
        }
    }

    private Boolean isMacValid(Record record) {
        ModifiableByteArray mac = record.getComputations().getMac();
        if (mac != null && mac.getValue() != null && mac.getValue().length > 0) {
            byte[] toBeMaced;
            toBeMaced = ArrayConverter.concatenate(record.getComputations().getAuthenticatedMetaData().getValue(),
                    record.getComputations().getNonMetaDataMaced().getValue());
            if (Arrays.equals(recordCipher.calculateMac(toBeMaced, context.getChooser().getMyConnectionPeer()),
                    mac.getValue())) {
                LOGGER.debug("Mac is valid");
                return true;
            } else {
                LOGGER.debug("Mac is invalid");
                return false;
            }
        } else {
            return null;
        }
    }

    private void prepareAdditionalMetadata(Record record) throws CryptoException {
        byte[] additionalAuthenticatedData = collectAdditionalAuthenticatedData(record, context.getChooser()
                .getSelectedProtocolVersion());
        record.getComputations().setAuthenticatedMetaData(additionalAuthenticatedData);
    }

    private void prepareNonMetaDataMaced(Record record, byte[] payload) throws CryptoException {
        if (recordCipher.isUsingTags() && !context.getChooser().getSelectedProtocolVersion().isTLS13()) {
            if (payload.length < recordCipher.getTagSize()) {
                throw new CryptoException("Ciphertext contains no tag");
            } else {
                record.getComputations().setNonMetaDataMaced(
                        Arrays.copyOfRange(payload, recordCipher.getTagSize(), payload.length));
            }
        } else {
            record.getComputations().setNonMetaDataMaced(payload);
        }
        LOGGER.debug("Setting NonMetaData Maced:"
                + ArrayConverter.bytesToHexString(record.getComputations().getNonMetaDataMaced()));
    }

    private boolean isEncryptThenMac(CipherSuite cipherSuite) {
        return context.isExtensionNegotiated(ExtensionType.ENCRYPT_THEN_MAC) && cipherSuite.isCBC()
                && recordCipher.isUsingMac();
    }

    private void adjustMac(Record record) throws CryptoException {
        byte[] cleanBytes;
        byte[] mac = parseMac(record.getComputations().getUnpaddedRecordBytes().getValue());
        record.getComputations().setMac(mac);
        cleanBytes = removeMac(record.getComputations().getUnpaddedRecordBytes().getValue());
        record.setCleanProtocolMessageBytes(cleanBytes);
    }

    private void useNoMac(Record record) {
        record.getComputations().setMac(new byte[0]);
        record.setCleanProtocolMessageBytes(record.getComputations().getUnpaddedRecordBytes().getValue());
    }

    private void useNoPadding(Record record) {
        record.getComputations().setPaddingLength(0);
        record.getComputations().setPadding(new byte[0]);
        record.getComputations().setUnpaddedRecordBytes(record.getComputations().getPlainRecordBytes());
    }

    private void adjustPaddingTLS13(Record record) throws CryptoException {
        byte[] unpadded = parseUnpaddedTLS13(record.getComputations().getPlainRecordBytes().getValue());
        byte contentMessageType = parseContentMessageType(unpadded);
        LOGGER.debug("Parsed ContentMessageType:" + contentMessageType);
        ProtocolMessageType contentType = ProtocolMessageType.getContentType(contentMessageType);
        if (contentType == null) {
            LOGGER.warn("Parsed unknown TLS 1.3 ProtocolMessage type. Using Unknown instead");
            contentType = ProtocolMessageType.UNKNOWN;
        }
        record.setContentMessageType(contentType);
        LOGGER.debug("ContentMessageType:" + record.getContentMessageType());
        byte[] unpaddedAndWithoutType = Arrays.copyOf(unpadded, unpadded.length - 1);
        record.getComputations().setUnpaddedRecordBytes(unpaddedAndWithoutType);
        LOGGER.debug("UnpaddedRecordBytes: "
                + ArrayConverter.bytesToHexString(record.getComputations().getUnpaddedRecordBytes().getValue()));
        byte[] padding = parsePadding(record.getComputations().getPlainRecordBytes().getValue(), record
                .getComputations().getPlainRecordBytes().getValue().length
                - unpadded.length);
        record.getComputations().setPadding(padding);
        LOGGER.debug("Padding: " + ArrayConverter.bytesToHexString(record.getComputations().getPadding().getValue()));
        record.getComputations().setPaddingLength(record.getComputations().getPadding().getValue().length);
        LOGGER.debug("PaddingLength: " + record.getComputations().getPaddingLength().getValue());
    }

    private void adjustPaddingTLS(Record record) throws CryptoException {
        int paddingLength = parsePaddingLength(record.getComputations().getPlainRecordBytes().getValue());
        record.getComputations().setPaddingLength(paddingLength);
        LOGGER.debug("PaddingLength: " + record.getComputations().getPaddingLength().getValue());
        byte[] unpadded = parseUnpadded(record.getComputations().getPlainRecordBytes().getValue(), paddingLength);
        record.getComputations().setUnpaddedRecordBytes(unpadded);
        LOGGER.debug("UnpaddedRecordBytes: "
                + ArrayConverter.bytesToHexString(record.getComputations().getUnpaddedRecordBytes().getValue()));
        byte[] padding = parsePadding(record.getComputations().getPlainRecordBytes().getValue(), paddingLength);
        record.getComputations().setPadding(padding);
        LOGGER.debug("Padding: " + ArrayConverter.bytesToHexString(record.getComputations().getPadding().getValue()));
        LOGGER.debug("Unpadded data:  {}", ArrayConverter.bytesToHexString(unpadded));
    }

    /**
     * Last byte contains the padding length. If there is no last byte, throw a
     * decyption exception (instead of index out of bounds)
     *
     * @param decrypted
     * @return
     */
    private int parsePaddingLength(byte[] decrypted) throws CryptoException {
        if (decrypted.length == 0) {
            throw new CryptoException("Could not extract padding.");
        }
        return decrypted[decrypted.length - 1];
    }

    private byte[] parseUnpadded(byte[] decrypted, int paddingLength) throws CryptoException {
        if (paddingLength > decrypted.length) {
            throw new CryptoException("Could not unpad decrypted Data. Padding length greater than data length");
        } else if (paddingLength == decrypted.length) {
            return new byte[0];
        }
        int paddingStart = decrypted.length - paddingLength - 1;
        return Arrays.copyOf(decrypted, paddingStart);
    }

    private byte[] parseUnpaddedTLS13(byte[] decrypted) throws CryptoException {
        if (decrypted.length == 0) {
            throw new CryptoException("Could not extract padding.");
        }
        int i = decrypted.length - 1;
        while (i >= 0 && decrypted[i] == 0) {
            --i;
        }
        return Arrays.copyOf(decrypted, i + 1);
    }

    private byte[] parsePadding(byte[] decrypted, int paddingLength) throws CryptoException {
        int paddingStart = decrypted.length - paddingLength - 1;
        if (paddingStart > decrypted.length) {
            throw new CryptoException("Could parse Padding. Padding start greater than data length");
        }
        if (paddingStart < 0) {
            throw new CryptoException("Could not parse Padding. Padding start is negative");
        }
        return Arrays.copyOfRange(decrypted, paddingStart, decrypted.length);
    }

    private byte[] parseMac(byte[] unpadded) throws CryptoException {
        if (unpadded.length - recordCipher.getMacLength() < 0) {
            throw new CryptoException("Could not parse MAC, not enough bytes left");
        }
        return Arrays.copyOfRange(unpadded, (unpadded.length - recordCipher.getMacLength()), unpadded.length);
    }

    private byte[] removeMac(byte[] unpadded) {
        return Arrays.copyOf(unpadded, (unpadded.length - recordCipher.getMacLength()));
    }

    private byte parseContentMessageType(byte[] unpadded) throws CryptoException {
        if (unpadded.length == 0) {
            throw new CryptoException("Could not extract content type of message.");
        }
        return unpadded[unpadded.length - 1];
    }

    private void checkForEndOfEarlyData(byte[] unpaddedBytes) throws CryptoException {
        byte[] endOfEarlyData = new byte[] { 5, 0, 0, 0 };
        if (Arrays.equals(unpaddedBytes, endOfEarlyData)) {
            adjustClientCipherAfterEarly();
        }
    }

    public void adjustClientCipherAfterEarly() throws CryptoException {
        try {
            context.setActiveClientKeySetType(Tls13KeySetType.HANDSHAKE_TRAFFIC_SECRETS);
            LOGGER.debug("Setting cipher for client to use handshake secrets");
            KeySet clientKeySet = KeySetGenerator.generateKeySet(context, context.getChooser()
                    .getSelectedProtocolVersion(), context.getActiveClientKeySetType());
            RecordCipher recordCipherClient = RecordCipherFactory.getRecordCipher(context, clientKeySet, context
                    .getChooser().getSelectedCipherSuite());
            context.getRecordLayer().setRecordCipher(recordCipherClient);
            context.getRecordLayer().updateDecryptionCipher();
            context.setReadSequenceNumber(0);
        } catch (NoSuchAlgorithmException ex) {
            LOGGER.error("Generating KeySet failed - Unknown algorithm");
            throw new WorkflowExecutionException(ex.toString());
        }
    }
}
