/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.record.crypto;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.RecordByteLength;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.record.BlobRecord;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipher;
import de.rub.nds.tlsattacker.core.state.TlsContext;

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
        byte[] cleanBytes = record.getCleanProtocolMessageBytes().getValue();
        if (recordCipher.isUseMac()) {
            byte[] toBeMaced;
            try {
                ByteArrayOutputStream stream = new ByteArrayOutputStream();
                stream.write(ArrayConverter.longToUint64Bytes(record.getSequenceNumber().getValue().longValue()));
                stream.write(record.getContentType().getValue());
                if (!context.getChooser().getSelectedProtocolVersion().isSSL()) {
                    stream.write(record.getProtocolVersion().getValue());
                }
                stream.write(ArrayConverter.intToBytes(record.getCleanProtocolMessageBytes().getValue().length,
                        RecordByteLength.RECORD_LENGTH)); // TODO
                stream.write(record.getCleanProtocolMessageBytes().getValue());
                toBeMaced = stream.toByteArray();
            } catch (IOException E) {
                throw new CryptoException("Could not create ToBeMaced Data", E);
            }
            byte[] mac = recordCipher.calculateMac(toBeMaced);
            setMac(record, mac);
            context.setSequenceNumber(context.getSequenceNumber() + 1);
        } else {
            record.setMac(new byte[0]);
        }
        setUnpaddedRecordBytes(record, cleanBytes);
        byte[] padding;
        if (context.getChooser().getSelectedProtocolVersion().isTLS13()) {
            padding = recordCipher.calculatePadding(record.getPaddingLength().getValue());
        } else {
            record.setPaddingLength(recordCipher.getPaddingLength(record.getUnpaddedRecordBytes().getValue().length));
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
        byte[] encrypted = recordCipher.encrypt(record.getPlainRecordBytes().getValue());
        setProtocolMessageBytes(record, encrypted);
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
}
