/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.record.serializer;

import de.rub.nds.tlsattacker.tls.constants.RecordByteLength;
import de.rub.nds.tlsattacker.tls.record.Record;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class RecordSerializer extends AbstractRecordSerializer<Record> {

    private final Record record;

    public RecordSerializer(Record record) {
        this.record = record;
    }

    @Override
    protected byte[] serializeBytes() {
        appendByte(record.getContentType().getValue());
        appendBytes(record.getProtocolVersion().getValue());
        appendInt(record.getLength().getValue(), RecordByteLength.RECORD_LENGTH);
        appendBytes(record.getProtocolMessageBytes().getValue());
        return getAlreadySerialized();
    }

}
