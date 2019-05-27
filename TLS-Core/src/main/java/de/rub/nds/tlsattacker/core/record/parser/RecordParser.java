/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.record.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.RecordByteLength;
import de.rub.nds.tlsattacker.core.record.Record;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class RecordParser extends AbstractRecordParser<Record> {

    private static final Logger LOGGER = LogManager.getLogger();

    public RecordParser(int startposition, byte[] array, ProtocolVersion version) {
        super(startposition, array, version);
    }

    @Override
    public Record parse() {
        LOGGER.debug("Parsing Record");
        Record record = new Record();
        parseContentType(record);
        ProtocolMessageType protocolMessageType = ProtocolMessageType
                .getContentType(record.getContentType().getValue());
        if (protocolMessageType == null) {
            protocolMessageType = ProtocolMessageType.UNKNOWN;
        }
        record.setContentMessageType(protocolMessageType);
        parseVersion(record);
        if (version.isDTLS()) {
            parseEpoch(record);
            parseSequenceNumber(record);
        }
        parseLength(record);
        parseProtocolMessageBytes(record);
        record.setCompleteRecordBytes(getAlreadyParsed());
        return record;
    }

    private void parseEpoch(Record record) {
        record.setEpoch(parseIntField(RecordByteLength.DTLS_EPOCH));
        LOGGER.debug("Epoch: " + record.getEpoch().getValue());
    }

    private void parseSequenceNumber(Record record) {
        record.setSequenceNumber(parseBigIntField(RecordByteLength.DTLS_SEQUENCE_NUMBER));
        LOGGER.debug("SequenceNumber: " + record.getSequenceNumber().getValue());
    }

    private void parseContentType(Record record) {
        record.setContentType(parseByteField(RecordByteLength.CONTENT_TYPE));
        LOGGER.debug("ContentType: " + record.getContentType().getValue());
    }

    private void parseVersion(Record record) {
        record.setProtocolVersion(parseByteArrayField(RecordByteLength.PROTOCOL_VERSION));
        LOGGER.debug("ProtocolVersion: " + ArrayConverter.bytesToHexString(record.getProtocolVersion().getValue()));
    }

    private void parseLength(Record record) {
        record.setLength(parseIntField(RecordByteLength.RECORD_LENGTH));
        LOGGER.debug("Length: " + record.getLength().getValue());
    }

    private void parseProtocolMessageBytes(Record record) {
        record.setProtocolMessageBytes(parseByteArrayField(record.getLength().getValue()));
        LOGGER.debug("ProtocolMessageBytes: "
                + ArrayConverter.bytesToHexString(record.getProtocolMessageBytes().getValue()));
    }
}
