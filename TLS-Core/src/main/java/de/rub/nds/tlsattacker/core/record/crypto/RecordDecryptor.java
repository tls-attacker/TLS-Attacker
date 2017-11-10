/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.record.crypto;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.record.BlobRecord;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipher;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.math.BigInteger;
import java.util.Arrays;

public class RecordDecryptor extends Decryptor {

    private final TlsContext context;

    public RecordDecryptor(RecordCipher recordCipher, TlsContext context) {
        super(recordCipher);
        this.context = context;
    }

    @Override
    public void decrypt(BlobRecord record) {
        LOGGER.debug("Decrypting BlobRecord");
        byte[] decrypted = recordCipher.decrypt(record.getProtocolMessageBytes().getValue());
        record.setCleanProtocolMessageBytes(decrypted);
        LOGGER.debug("CleanProtocolMessageBytes: "
                + ArrayConverter.bytesToHexString(record.getCleanProtocolMessageBytes().getValue()));
    }

    @Override
    public void decrypt(Record record) {
        LOGGER.debug("Decrypting Record");
        record.setSequenceNumber(BigInteger.valueOf(context.getReadSequenceNumber()));
        byte[] encrypted = record.getProtocolMessageBytes().getValue();
        CipherSuite cipherSuite = context.getChooser().getSelectedCipherSuite();
        prepareAdditionalMetadata(record, encrypted);

        if (isEncryptThenMac(cipherSuite)) {
            LOGGER.trace("EncryptThenMac is active");
            byte[] mac = parseMac(record.getProtocolMessageBytes().getValue());
            record.setMac(mac);
            encrypted = removeMac(record.getProtocolMessageBytes().getValue());
        }
        LOGGER.debug("Decrypting:" + ArrayConverter.bytesToHexString(encrypted));
        byte[] decrypted = recordCipher.decrypt(encrypted);

        record.setPlainRecordBytes(decrypted);
        LOGGER.debug("PlainRecordBytes: " + ArrayConverter.bytesToHexString(record.getPlainRecordBytes().getValue()));
        if (recordCipher.isUsingPadding()) {
            if (!context.getChooser().getSelectedProtocolVersion().isTLS13()) {
                adjustPaddingTLS(record);
            } else {
                adjustPaddingTLS13(record);
            }
        } else {
            useNoPadding(record);
        }
        if (!isEncryptThenMac(cipherSuite) && recordCipher.isUsingMac()) {
            LOGGER.trace("EncryptThenMac is not active");
            prepareAdditionalMetadata(record, record.getUnpaddedRecordBytes().getValue());
            if (cipherSuite.isUsingMac()) {
                adjustMac(record);
            } else {
                useNoMac(record);
            }
        } else {
            useNoMac(record);
        }
        context.increaseReadSequenceNumber();
    }

    private void prepareAdditionalMetadata(Record record, byte[] payload) {
        prepareNonMetaDataMaced(record, payload);
        byte[] additionalAuthenticatedData = collectAdditionalAuthenticatedData(record, context.getChooser()
                .getSelectedProtocolVersion());
        recordCipher.setAdditionalAuthenticatedData(additionalAuthenticatedData);
    }

    private void prepareNonMetaDataMaced(Record record, byte[] payload) {
        if (recordCipher.isUsingTags() && !context.getChooser().getSelectedProtocolVersion().isTLS13()) {
            if (payload.length < recordCipher.getTagSize()) {
                throw new CryptoException("Ciphertext contains no tag");
            } else {
                record.setNonMetaDataMaced(Arrays.copyOfRange(payload, recordCipher.getTagSize(), payload.length));
            }
        } else {
            record.setNonMetaDataMaced(payload);
        }
        LOGGER.debug("Setting NonMetaData Maced:" + ArrayConverter.bytesToHexString(record.getNonMetaDataMaced()));
    }

    private boolean isEncryptThenMac(CipherSuite cipherSuite) {
        return context.isExtensionNegotiated(ExtensionType.ENCRYPT_THEN_MAC) && cipherSuite.isCBC()
                && recordCipher.isUsingMac();
    }

    private void adjustMac(Record record) {
        byte[] cleanBytes;
        byte[] mac = parseMac(record.getUnpaddedRecordBytes().getValue());
        record.setMac(mac);
        cleanBytes = removeMac(record.getUnpaddedRecordBytes().getValue());
        record.setCleanProtocolMessageBytes(cleanBytes);
    }

    private void useNoMac(Record record) {
        record.setMac(new byte[0]);
        record.setCleanProtocolMessageBytes(record.getUnpaddedRecordBytes().getValue());
    }

    private void useNoPadding(Record record) {
        record.setPaddingLength(0);
        record.setPadding(new byte[0]);
        record.setUnpaddedRecordBytes(record.getPlainRecordBytes());
    }

    private void adjustPaddingTLS13(Record record) {
        byte[] unpadded = parseUnpaddedTLS13(record.getPlainRecordBytes().getValue());
        byte contentMessageType = parseContentMessageType(unpadded);
        LOGGER.info("Parsed ContentMessageType:" + contentMessageType);
        record.setContentMessageType(ProtocolMessageType.getContentType(contentMessageType));
        LOGGER.info("ContentMessageType:" + record.getContentMessageType());
        byte[] unpaddedAndWithoutType = Arrays.copyOf(unpadded, unpadded.length - 1);
        record.setUnpaddedRecordBytes(unpaddedAndWithoutType);
        LOGGER.debug("UnpaddedRecordBytes: "
                + ArrayConverter.bytesToHexString(record.getUnpaddedRecordBytes().getValue()));
        byte[] padding = parsePadding(record.getPlainRecordBytes().getValue(),
                record.getPlainRecordBytes().getValue().length - unpadded.length);
        record.setPadding(padding);
        LOGGER.debug("Padding: " + ArrayConverter.bytesToHexString(record.getPadding().getValue()));
        record.setPaddingLength(record.getPadding().getValue().length);
        LOGGER.debug("PaddingLength: " + record.getPaddingLength().getValue());
    }

    private void adjustPaddingTLS(Record record) {
        int paddingLength = parsePaddingLength(record.getPlainRecordBytes().getValue());
        record.setPaddingLength(paddingLength);
        LOGGER.debug("PaddingLength: " + record.getPaddingLength().getValue());
        byte[] unpadded = parseUnpadded(record.getPlainRecordBytes().getValue(), paddingLength);
        record.setUnpaddedRecordBytes(unpadded);
        LOGGER.debug("UnpaddedRecordBytes: "
                + ArrayConverter.bytesToHexString(record.getUnpaddedRecordBytes().getValue()));
        byte[] padding = parsePadding(record.getPlainRecordBytes().getValue(), paddingLength);
        record.setPadding(padding);
        LOGGER.debug("Padding: " + ArrayConverter.bytesToHexString(record.getPadding().getValue()));
        LOGGER.debug("Unpadded data:  {}", ArrayConverter.bytesToHexString(unpadded));
    }

    /**
     * Last byte contains the padding length. If there is no last byte, throw a
     * decyption exception (instead of index out of bounds)
     *
     * @param decrypted
     * @return
     */
    private int parsePaddingLength(byte[] decrypted) {
        if (decrypted.length == 0) {
            throw new CryptoException("Could not extract padding.");
        }
        return decrypted[decrypted.length - 1];
    }

    private byte[] parseUnpadded(byte[] decrypted, int paddingLength) {
        if (paddingLength > decrypted.length) {
            throw new CryptoException("Could not unpad decrypted Data. Padding length greater than data length");
        }
        int paddingStart = decrypted.length - paddingLength - 1;
        return Arrays.copyOf(decrypted, paddingStart);
    }

    private byte[] parseUnpaddedTLS13(byte[] decrypted) {
        if (decrypted.length == 0) {
            throw new CryptoException("Could not extract padding.");
        }
        int i = decrypted.length - 1;
        while (i >= 0 && decrypted[i] == 0) {
            --i;
        }
        return Arrays.copyOf(decrypted, i + 1);
    }

    private byte[] parsePadding(byte[] decrypted, int paddingLength) {
        int paddingStart = decrypted.length - paddingLength - 1;
        if (paddingStart > decrypted.length) {
            throw new CryptoException("Could parse Padding. Padding start greater than data length");
        }
        return Arrays.copyOfRange(decrypted, paddingStart, decrypted.length);
    }

    private byte[] parseMac(byte[] unpadded) {
        if (unpadded.length - recordCipher.getMacLength() < 0) {
            throw new CryptoException("Could not parse MAC, not enough bytes left");
        }
        return Arrays.copyOfRange(unpadded, (unpadded.length - recordCipher.getMacLength()), unpadded.length);
    }

    private byte[] removeMac(byte[] unpadded) {
        return Arrays.copyOf(unpadded, (unpadded.length - recordCipher.getMacLength()));
    }

    private byte parseContentMessageType(byte[] unpadded) {
        if (unpadded.length == 0) {
            throw new CryptoException("Could not extract content type of message.");
        }
        return unpadded[unpadded.length - 1];
    }
}
