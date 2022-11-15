/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.record.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.RecordByteLength;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.layer.data.Parser;
import de.rub.nds.tlsattacker.core.record.Record;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class RecordParser extends Parser<Record> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final ProtocolVersion version;
    private final TlsContext tlsContext;

    public RecordParser(InputStream stream, ProtocolVersion version, TlsContext tlsContext) {
        super(stream);
        this.version = version;
        this.tlsContext = tlsContext;
    }

    @Override
    public void parse(Record record) {
        LOGGER.debug("Parsing Record");
        boolean isDtls13Header = parseContentType(record);
        if (isDtls13Header) {
            parseDtls13Header(record, getAlreadyParsed()[0]);
        } else {
            ProtocolMessageType protocolMessageType =
                    ProtocolMessageType.getContentType(record.getContentType().getValue());
            if (protocolMessageType == null) {
                protocolMessageType = ProtocolMessageType.UNKNOWN;
            }
            record.setContentMessageType(protocolMessageType);
            parseVersion(record);
            if (version.isDTLS()) {
                parseEpoch(record);
                parseSequenceNumber(record, RecordByteLength.DTLS_SEQUENCE_NUMBER);
                if (protocolMessageType == ProtocolMessageType.TLS12_CID) {
                    parseConnectionId(record);
                }
            }
            parseLength(record);
        }

        parseProtocolMessageBytes(record);
    }

    private void parseEpoch(Record record) {
        record.setEpoch(parseIntField(RecordByteLength.DTLS_EPOCH));
        LOGGER.debug("Epoch: " + record.getEpoch().getValue());
    }

    private void parseSequenceNumber(Record record, int length) {
        record.setSequenceNumber(parseBigIntField(length));
        LOGGER.debug("SequenceNumber: " + record.getSequenceNumber().getValue());
    }

    private void parseConnectionId(Record record) {
        int connectionIdLength =
                tlsContext
                        .getRecordLayer()
                        .getDecryptor()
                        .getRecordCipher(record.getEpoch().getValue())
                        .getState()
                        .getConnectionId()
                        .length;
        record.setConnectionId(parseByteArrayField(connectionIdLength));
        LOGGER.debug(
                "ConnectionID: "
                        + ArrayConverter.bytesToHexString(record.getConnectionId().getValue()));
    }

    private boolean parseContentType(Record record) {
        byte contentType = parseByteField(RecordByteLength.CONTENT_TYPE);
        // if contentType starts with 001 it is a DTLS 1.3 unified header
        if ((contentType & 0xE0) == 0x20) {
            return true;
        } else {
            LOGGER.debug("ContentType: " + record.getContentType().getValue());
            return false;
        }
    }

    private void parseDtls13Header(Record record, byte firstByte) {
        //parse first byte
        boolean isConnectionIdPresent = (firstByte & 0x10) == 0x10;
        boolean sequenceNumberLength = (firstByte & 0x08) == 0x08;
        boolean isLengthPresent = (firstByte & 0x04) == 0x04;
        int lowerEpoch = firstByte & 0x03;
        record.setEpoch(lowerEpoch);
        LOGGER.debug("Epoch (lower 2 bits): " + lowerEpoch);

        if (isConnectionIdPresent) {
            parseConnectionId(record);
        }
        if (sequenceNumberLength == false) {// 8 bit sequence number
            parseSequenceNumber(record, RecordByteLength.DTLS13_SEQUENCE_NUMBER_HEADER_SHORT);
        } else { // 16 bit sequence number
            parseSequenceNumber(record, RecordByteLength.DTLS13_SEQUENCE_NUMBER_HEADER_LONG);
        }
        if (isLengthPresent) {
            parseLength(record);
        }

    }

    private void parseVersion(Record record) {
        record.setProtocolVersion(parseByteArrayField(RecordByteLength.PROTOCOL_VERSION));
        LOGGER.debug(
                "ProtocolVersion: "
                        + ArrayConverter.bytesToHexString(record.getProtocolVersion().getValue()));
    }

    private void parseLength(Record record) {
        record.setLength(parseIntField(RecordByteLength.RECORD_LENGTH));
        LOGGER.debug("Length: " + record.getLength().getValue());
    }

    private void parseProtocolMessageBytes(Record record) {
        // if length is not set, entire rest of the record is protocol message (DTLS 1.3 header)
        if (record.getLength().getValue() != null) {
            record.setProtocolMessageBytes(parseByteArrayField(record.getLength().getValue()));
        } else {
            record.setProtocolMessageBytes(parseByteArrayField(getBytesLeft()));
        }
        LOGGER.debug(
                "ProtocolMessageBytes: "
                        + ArrayConverter.bytesToHexString(
                                record.getProtocolMessageBytes().getValue()));
    }
}
