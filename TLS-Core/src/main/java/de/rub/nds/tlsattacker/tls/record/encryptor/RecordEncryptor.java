/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.record.encryptor;

import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.constants.RecordByteLength;
import de.rub.nds.tlsattacker.tls.exceptions.CryptoException;
import de.rub.nds.tlsattacker.tls.record.Record;
import de.rub.nds.tlsattacker.tls.record.cipher.RecordCipher;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class RecordEncryptor extends Encryptor<Record> {

    private int sequenceNumber = 0;
    private final ProtocolVersion version;

    public RecordEncryptor(RecordCipher recordCipher, ProtocolVersion version) {
        super(recordCipher);
        this.version = version;
    }

    @Override
    public void encrypt(Record record) {
        byte[] cleanBytes = record.getCleanProtocolMessageBytes().getValue();
        if (recordCipher.isUseMac()) {
            byte[] toBeMaced = new byte[0];
            try {
                ByteArrayOutputStream stream = new ByteArrayOutputStream();
                stream.write(ArrayConverter.intToBytes(sequenceNumber, RecordByteLength.SEQUENCE_NUMBER));
                stream.write(record.getContentMessageType().getValue());
                stream.write(record.getProtocolVersion().getValue());
                stream.write(ArrayConverter.intToBytes(record.getCleanProtocolMessageBytes().getValue().length,
                        RecordByteLength.RECORD_LENGTH)); // TODO
                stream.write(record.getCleanProtocolMessageBytes().getValue());
                toBeMaced = stream.toByteArray();
                sequenceNumber++;
            } catch (IOException E) {
                throw new CryptoException("Could not create ToBeMaced Data", E);
            }
            byte[] mac = recordCipher.calculateMac(toBeMaced);
            record.setMac(mac);
        } else {
            record.setMac(new byte[0]);
        }
        if (version == ProtocolVersion.TLS13) {
            record.setUnpaddedRecordBytes(ArrayConverter.concatenate(cleanBytes, record.getMac().getValue(), record.getContentMessageType().getArrayValue()));
        } else {
            record.setUnpaddedRecordBytes(ArrayConverter.concatenate(cleanBytes, record.getMac().getValue()));
        }
        if (recordCipher.isUsePadding()) {
            byte[] padding;
            if (version == ProtocolVersion.TLS13) {
                padding = recordCipher.calculatePadding(record.getPaddingLength().getValue());
            } else {
                padding = recordCipher.calculatePadding(recordCipher.getPaddingLength(record.getUnpaddedRecordBytes().getValue().length));
            }
            record.setPadding(padding);
            record.setPaddingLength(record.getPadding().getValue().length);
            byte[] plain;
            if (version == ProtocolVersion.TLS13) {
                plain = ArrayConverter.concatenate(record.getUnpaddedRecordBytes().getValue(), record.getPadding().getValue());
            } else {
                plain = ArrayConverter.concatenate(record.getUnpaddedRecordBytes().getValue(), record.getPadding().getValue(),
                        record.getPaddingLength().getValue());
            }
            record.setPlainRecordBytes(plain);
        } else {
            record.setPadding(new byte[0]);
            record.setPaddingLength(0);
            record.setPlainRecordBytes(record.getUnpaddedRecordBytes());
        }
        byte[] encrypted = recordCipher.encrypt(record.getPlainRecordBytes().getValue());
        record.setProtocolMessageBytes(encrypted);
    }
}
