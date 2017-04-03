/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.record.encryptor;

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

    private static final Logger LOGGER = LogManager.getLogger("ENCRYPTOR");

    private RecordCipher recordCipher;

    private int sequenceNumber = 0;
    
    public RecordEncryptor(RecordCipher recordCipher) {
        this.recordCipher = recordCipher;
    }

    public RecordCipher getRecordCipher() {
        return recordCipher;
    }

    public void setRecordCipher(RecordCipher recordCipher) {
        this.recordCipher = recordCipher;
    }

    @Override
    public void encrypt(Record record) {
        byte[] cleanBytes = record.getCleanProtocolMessageBytes().getValue();
        if (recordCipher.isUseMac()) {
            byte[] toBeMaced = new byte[0];
            try {
                ByteArrayOutputStream stream = new ByteArrayOutputStream();
                stream.write(ArrayConverter.intToBytes(sequenceNumber, RecordByteLength.SEQUENCE_NUMBER));
                stream.write(record.getContentType().getValue());
                stream.write(record.getProtocolVersion().getValue());
                stream.write(ArrayConverter.intToBytes(record.getCleanProtocolMessageBytes().getValue().length,RecordByteLength.RECORD_LENGTH)); //TODO
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
        record.setUnpaddedRecordBytes(ArrayConverter.concatenate(record.getCleanProtocolMessageBytes().getValue(),
                record.getMac().getValue()));
        byte[] padding = recordCipher.calculatePadding(recordCipher.getPaddingLength(record.getUnpaddedRecordBytes()
                .getValue().length));
        record.setPadding(padding);
        record.setPaddingLength(record.getPadding().getValue().length);
        byte[] plain = ArrayConverter.concatenate(record.getUnpaddedRecordBytes().getValue(), record.getPadding()
                .getValue(), record.getPaddingLength().getValue());
        record.setPlainRecordBytes(plain);
        byte[] encrypted = recordCipher.encrypt(record.getPlainRecordBytes().getValue());
        record.setProtocolMessageBytes(encrypted);
    }
}
