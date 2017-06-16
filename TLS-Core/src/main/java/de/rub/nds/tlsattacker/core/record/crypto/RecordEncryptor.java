/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.record.crypto;

import de.rub.nds.tlsattacker.core.constants.RecordByteLength;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipher;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class RecordEncryptor extends Encryptor<Record> {

    private final TlsContext context;

    public RecordEncryptor(RecordCipher recordCipher, TlsContext context) {
        super(recordCipher);
        this.context = context;
    }

    @Override
    public void encrypt(Record record) {
        byte[] cleanBytes = record.getCleanProtocolMessageBytes().getValue();
        if (recordCipher.isUseMac()) {
            byte[] toBeMaced = new byte[0];
            try {
                ByteArrayOutputStream stream = new ByteArrayOutputStream();
                stream.write(ArrayConverter.longToUint64Bytes(record.getSequenceNumber().getValue().longValue()));
                stream.write(record.getContentType().getValue());
                stream.write(record.getProtocolVersion().getValue());
                stream.write(ArrayConverter.intToBytes(record.getCleanProtocolMessageBytes().getValue().length,
                        RecordByteLength.RECORD_LENGTH)); // TODO
                stream.write(record.getCleanProtocolMessageBytes().getValue());
                toBeMaced = stream.toByteArray();
            } catch (IOException E) {
                throw new CryptoException("Could not create ToBeMaced Data", E);
            }
            byte[] mac = recordCipher.calculateMac(toBeMaced);
            record.setMac(mac);
            context.setSequenceNumber(context.getSequenceNumber() + 1);
        } else {
            record.setMac(new byte[0]);
        }
        record.setUnpaddedRecordBytes(ArrayConverter.concatenate(cleanBytes, record.getMac().getValue()));
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
