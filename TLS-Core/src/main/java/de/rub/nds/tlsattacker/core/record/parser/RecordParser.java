/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.record.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.RecordByteLength;
import de.rub.nds.tlsattacker.core.layer.data.Parser;
import de.rub.nds.tlsattacker.core.record.Record;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class RecordParser extends Parser<Record> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final ProtocolVersion version;

    public RecordParser(InputStream stream, ProtocolVersion version) {
        super(stream);
        this.version = version;
    }

    @Override
    public void parse(Record record) {
        LOGGER.debug("Parsing Record");
        parseContentType(record);
        ProtocolMessageType protocolMessageType =
            ProtocolMessageType.getContentType(record.getContentType().getValue());
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
        LOGGER.debug(
            "ProtocolMessageBytes: " + ArrayConverter.bytesToHexString(record.getProtocolMessageBytes().getValue()));
    }
}
