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
import de.rub.nds.tlsattacker.core.constants.RecordByteLength;
import de.rub.nds.tlsattacker.core.record.BlobRecord;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipher;
import static de.rub.nds.tlsattacker.core.record.crypto.Encryptor.LOGGER;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.math.BigInteger;

/**
 * @author Robert Merget <robert.merget@rub.de>
 * @author Nurullah Erinola <nurullah.erinola@rub.de>
 */
public class RecordEncryptor extends Encryptor {

    private final TlsContext context;

    public RecordEncryptor(RecordCipher recordCipher, TlsContext context) {
        super(recordCipher);
        this.context = context;
    }

    @Override
    public void encrypt(BlobRecord record) {
        LOGGER.debug("Encrypting BlobRecord");
        byte[] encrypted = recordCipher.encrypt(record.getCleanProtocolMessageBytes().getValue());
        record.setProtocolMessageBytes(encrypted);
        LOGGER.debug("ProtocolMessageBytes: "
                + ArrayConverter.bytesToHexString(record.getProtocolMessageBytes().getValue()));
    }

    @Override
    public void encrypt(Record record) {
        LOGGER.debug("Encrypting Record:");
        // initialising mac
        record.setMac(new byte[0]);
        byte[] cleanBytes = record.getCleanProtocolMessageBytes().getValue();
        byte[] additionalAuthenticatedData = collectAdditionalAuthenticatedData(record);
        CipherSuite cipherSuite = context.getChooser().getSelectedCipherSuite();
        if (!context.isEncryptThenMacExtensionSentByServer()) {
            byte[] mac = recordCipher.calculateMac(ArrayConverter.concatenate(additionalAuthenticatedData, cleanBytes));
            setMac(record, mac);
        }
        setUnpaddedRecordBytes(record, cleanBytes);

        byte[] padding;
        if (context.getChooser().getSelectedProtocolVersion().isTLS13()) {
            padding = recordCipher.calculatePadding(record.getPaddingLength().getValue());
        } else {
            int paddingLength = recordCipher.calculatePaddingLength(record.getUnpaddedRecordBytes().getValue().length);
            record.setPaddingLength(paddingLength);
            padding = recordCipher.calculatePadding(record.getPaddingLength().getValue());
        }
        setPadding(record, padding);
        setPaddingLength(record);
        byte[] plain;
        if (context.getChooser().getSelectedProtocolVersion().isTLS13() && context.isEncryptActive()) {
            plain = ArrayConverter.concatenate(record.getUnpaddedRecordBytes().getValue(), record
                    .getContentMessageType().getArrayValue(), record.getPadding().getValue());
        } else {
            plain = ArrayConverter.concatenate(record.getUnpaddedRecordBytes().getValue(), record.getPadding()
                    .getValue());
        }
        setPlainRecordBytes(record, plain);
        recordCipher.setAdditionalAuthenticatedData(additionalAuthenticatedData);
        byte[] encrypted = recordCipher.encrypt(record.getPlainRecordBytes().getValue());
        if (context.isEncryptThenMacExtensionSentByServer() && cipherSuite.isCBC() && recordCipher.isUsingMac()) {
            byte[] mac = recordCipher.calculateMac(ArrayConverter.concatenate(additionalAuthenticatedData, encrypted));
            setMac(record, mac);
            encrypted = ArrayConverter.concatenate(encrypted, record.getMac().getValue());
        }
        setProtocolMessageBytes(record, encrypted);
        context.increaseWriteSequenceNumber();
    }

    private void setMac(Record record, byte[] mac) {
        record.setMac(mac);
        LOGGER.debug("MAC: " + ArrayConverter.bytesToHexString(record.getMac().getValue()));
    }

    private void setUnpaddedRecordBytes(Record record, byte[] cleanBytes) {
        record.setUnpaddedRecordBytes(ArrayConverter.concatenate(cleanBytes, record.getMac().getValue()));
        LOGGER.debug("UnpaddedRecordBytes: "
                + ArrayConverter.bytesToHexString(record.getUnpaddedRecordBytes().getValue()));
    }

    private void setPadding(Record record, byte[] padding) {
        record.setPadding(padding);
        LOGGER.debug("Padding: " + ArrayConverter.bytesToHexString(record.getPadding().getValue()));
    }

    private void setPaddingLength(Record record) {
        record.setPaddingLength(record.getPadding().getValue().length);
        LOGGER.debug("PaddingLength: " + record.getPaddingLength().getValue());
    }

    private void setPlainRecordBytes(Record record, byte[] plain) {
        record.setPlainRecordBytes(plain);
        LOGGER.debug("PlainRecordBytes: " + ArrayConverter.bytesToHexString(record.getPlainRecordBytes().getValue()));
    }

    private void setProtocolMessageBytes(Record record, byte[] encrypted) {
        record.setProtocolMessageBytes(encrypted);
        LOGGER.debug("ProtocolMessageBytes: "
                + ArrayConverter.bytesToHexString(record.getProtocolMessageBytes().getValue()));
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
                || record.getCleanProtocolMessageBytes() == null) {
            return new byte[0];
        }
        byte[] seqNumber = ArrayConverter.longToUint64Bytes(record.getSequenceNumber().getValue().longValue());
        byte[] contentType = { record.getContentType().getValue() };
        int length = record.getCleanProtocolMessageBytes().getValue().length;
        byte[] byteLength = ArrayConverter.intToBytes(length, RecordByteLength.RECORD_LENGTH);
        byte[] result = ArrayConverter.concatenate(seqNumber, contentType, record.getProtocolVersion().getValue(),
                byteLength);
        return result;
    }
}
