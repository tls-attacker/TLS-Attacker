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
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.RecordByteLength;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.record.BlobRecord;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipher;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.math.BigInteger;
import java.util.Arrays;

/**
 * @author Robert Merget <robert.merget@rub.de>
 * @author Nurullah Erinola <nurullah.erinola@rub.de>
 */
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
        byte[] addtionalAuthenticatedData = collectAdditionalAuthenticatedData(record);
        recordCipher.setAdditionalAuthenticatedData(addtionalAuthenticatedData);
        if (context.isEncryptThenMacExtensionSentByServer() && cipherSuite.isCBC() && recordCipher.isUsingMac()) {
            byte[] mac = parseMac(record.getProtocolMessageBytes().getValue());
            record.setMac(mac);
            byte[] unmacedBytes = removeMac(record.getProtocolMessageBytes().getValue());
            record.setUnpaddedRecordBytes(unmacedBytes);// ???
        }
        byte[] decrypted = recordCipher.decrypt(encrypted);
        record.setPlainRecordBytes(decrypted);
        LOGGER.debug("PlainRecordBytes: " + ArrayConverter.bytesToHexString(record.getPlainRecordBytes().getValue()));
        byte[] plainBytes = record.getPlainRecordBytes().getValue();
        if (recordCipher.isUsingPadding()) {
            if (!context.getChooser().getSelectedProtocolVersion().isTLS13()) {
                adjustPaddingTLS(record);
            } else {
                adjustPaddingTLS13(record);
            }
        } else {
            useNoPadding(record);
        }
        if (recordCipher.isUsingMac()) {
            adjustMac(record);
        } else {
            useNoMac(record);
        }
        context.increaseReadSequenceNumber();
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
        record.setContentMessageType(ProtocolMessageType.getContentType(contentMessageType));
        byte[] unpaddedAndWithoutType = Arrays.copyOf(unpadded, unpadded.length - 1);
        record.setUnpaddedRecordBytes(unpaddedAndWithoutType);
        LOGGER.debug("UnpaddedRecordBytes: "
                + ArrayConverter.bytesToHexString(record.getUnpaddedRecordBytes().getValue()));
        byte[] padding = parsePadding(record.getPlainRecordBytes().getValue(),
                record.getPlainRecordBytes().getValue().length - unpadded.length);
        record.setPadding(padding);
        LOGGER.debug("Padding: " + ArrayConverter.bytesToHexString(record.getPadding().getValue()));
        record.setPaddingLength(padding.length);
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
            throw new CryptoException("Could not extract content tpye of message.");
        }
        return unpadded[unpadded.length - 1];
    }

    /**
     * This function collects data needed for computing MACs and other
     * authentication tags in CBC/CCM/GCM cipher suites.
     *
     * From the Lucky13 paper: An individual record R (viewed as a byte sequence
     * of length at least zero) is processed as follows. The sender maintains an
     * 8-byte sequence number SQN which is incremented for each record sent, and
     * forms a 5-byte field HDR consisting of a 1-byte type field, a 2-byte
     * version field, and a 2-byte length field. It then calculates a MAC over
     * the bytes SQN || HDR || R.
     *
     * When we are decrypting a ciphertext, the difference between the
     * ciphertext length and plaintext length has to be subtracted from the
     * record length.
     *
     * @param record
     * @param plainCipherDifference
     * @return
     */
    @Override
    protected byte[] collectAdditionalAuthenticatedData(Record record) {
        if (record.getSequenceNumber() == null || record.getContentType() == null
                || record.getProtocolMessageBytes() == null) {
            return new byte[0];
        }
        byte[] seqNumber = ArrayConverter.longToUint64Bytes(record.getSequenceNumber().getValue().longValue());
        byte[] contentType = { record.getContentType().getValue() };
        int length = record.getProtocolMessageBytes().getValue().length;
        length -= recordCipher.getPlainCipherLengthDifference();
        byte[] byteLength = ArrayConverter.intToBytes(length, RecordByteLength.RECORD_LENGTH);
        byte[] result = ArrayConverter.concatenate(seqNumber, contentType, record.getProtocolVersion().getValue(),
                byteLength);
        return result;
    }
}
