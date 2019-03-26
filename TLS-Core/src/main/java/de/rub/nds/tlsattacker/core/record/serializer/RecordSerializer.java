/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.record.serializer;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.RecordByteLength;
import de.rub.nds.tlsattacker.core.record.Record;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class RecordSerializer extends AbstractRecordSerializer<Record> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final Record record;

    public RecordSerializer(Record record) {
        this.record = record;
    }

    @Override
    protected byte[] serializeBytes() {
        LOGGER.debug("Serializing Record");
        writeContentType(record);
        writeProtocolVersion(record);
        if (record.getEpoch() != null) {
            appendInt(record.getEpoch().getValue(), RecordByteLength.DTLS_EPOCH);
            appendBigInteger(record.getSequenceNumber().getValue(), RecordByteLength.DTLS_SEQUENCE_NUMBER);
        }
        writeLength(record);
        writeProtocolMessageBytes(record);
        return getAlreadySerialized();
    }

    private void writeContentType(Record record) {
        appendByte(record.getContentType().getValue());
        LOGGER.debug("ContentType: " + record.getContentType().getValue());
    }

    private void writeProtocolVersion(Record record) {
        appendBytes(record.getProtocolVersion().getValue());
        LOGGER.debug("ProtocolVersion: " + ArrayConverter.bytesToHexString(record.getProtocolVersion().getValue()));
    }

    private void writeLength(Record record) {
        appendInt(record.getLength().getValue(), RecordByteLength.RECORD_LENGTH);
        LOGGER.debug("Length: " + record.getLength().getValue());
    }

    private void writeProtocolMessageBytes(Record record) {
        appendBytes(record.getProtocolMessageBytes().getValue());
        LOGGER.debug("ProtocolMessageBytes: "
                + ArrayConverter.bytesToHexString(record.getProtocolMessageBytes().getValue()));
    }

}
