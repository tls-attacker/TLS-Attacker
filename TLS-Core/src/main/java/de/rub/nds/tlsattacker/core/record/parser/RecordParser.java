/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.record.parser;

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
            record.setProtocolVersion(ProtocolVersion.DTLS13.getValue());
            parseDtls13Header(record, record.getUnifiedHeader().getValue());
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
                parseSequenceNumber(record);
                if (protocolMessageType == ProtocolMessageType.TLS12_CID) {
                    parseConnectionId(record);
                }
            }
            parseLength(record);
        }

        parseProtocolMessageBytes(record);
        record.setCompleteRecordBytes(getAlreadyParsed());
    }

    private void parseEpoch(Record record) {
        record.setEpoch(parseIntField(RecordByteLength.DTLS_EPOCH));
        LOGGER.debug("Epoch: " + record.getEpoch().getValue());
    }

    private void parseSequenceNumber(Record record) {
        record.setSequenceNumber(parseBigIntField(RecordByteLength.DTLS_SEQUENCE_NUMBER));
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
        LOGGER.debug("ConnectionID: {}", record.getConnectionId().getValue());
    }

    private boolean parseContentType(Record record) {
        byte firstByte = parseByteField(RecordByteLength.CONTENT_TYPE);
        // if contentType starts with 001 it is a DTLS 1.3 unified header
        if ((firstByte & 0xE0) == 0x20) {
            record.setUnifiedHeader(firstByte);
            LOGGER.debug("UnifiedHeader: 00" + Integer.toBinaryString(firstByte));
            return true;
        } else {
            record.setContentType(firstByte);
            LOGGER.debug("ContentType: " + record.getContentType().getValue());
            return false;
        }
    }

    private void parseDtls13Header(Record record, byte firstByte) {
        // parse first byte
        boolean isConnectionIdPresent = (firstByte & 0x10) == 0x10;
        boolean sequenceNumberLength = (firstByte & 0x08) == 0x08;
        boolean isLengthPresent = (firstByte & 0x04) == 0x04;
        int lowerEpoch = firstByte & 0x03;
        record.setEpoch(lowerEpoch);
        LOGGER.debug("Epoch (lower 2 bits): " + lowerEpoch);

        if (isConnectionIdPresent) {
            parseConnectionId(record);
        }
        if (sequenceNumberLength == false) { // 8 bit sequence number
            record.setEncryptedSequenceNumber(
                    parseByteArrayField(RecordByteLength.DTLS13_SEQUENCE_NUMBER_HEADER_SHORT));
        } else { // 16 bit sequence number
            record.setEncryptedSequenceNumber(
                    parseByteArrayField(RecordByteLength.DTLS13_SEQUENCE_NUMBER_HEADER_LONG));
        }
        LOGGER.debug(
                "Encrypted SequenceNumber: {}", record.getEncryptedSequenceNumber().getValue());
        if (isLengthPresent) {
            parseLength(record);
        }
    }

    private void parseVersion(Record record) {
        record.setProtocolVersion(parseByteArrayField(RecordByteLength.PROTOCOL_VERSION));
        LOGGER.debug("ProtocolVersion: {}", record.getProtocolVersion().getValue());
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
        LOGGER.debug("ProtocolMessageBytes: {}", record.getProtocolMessageBytes().getValue());
    }
}
