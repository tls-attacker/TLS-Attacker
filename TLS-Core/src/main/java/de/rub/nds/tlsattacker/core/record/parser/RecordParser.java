/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
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
        boolean isContentType = !parseContentType(record);
        if (!isContentType) {
            record.setProtocolVersion(ProtocolVersion.DTLS13.getValue());
            parseDtls13Header(record);
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
            return false;
        } else {
            record.setContentType(firstByte);
            LOGGER.debug("ContentType: " + record.getContentType().getValue());
            return true;
        }
    }

    private void parseDtls13Header(Record record) {
        byte header = record.getUnifiedHeader().getValue();
        int lowerEpoch = header & 0x03;
        record.setEpoch(lowerEpoch);
        boolean isConnectionIdPresent = (header & 0x10) == 0x10;
        if (isConnectionIdPresent) {
            parseConnectionId(record);
        }
        boolean isSequenceNumberLengthLong = (header & 0x08) == 0x08;
        if (isSequenceNumberLengthLong) {
            record.setEncryptedSequenceNumber(
                    parseByteArrayField(RecordByteLength.DTLS13_CIPHERTEXT_SEQUENCE_NUMBER_LONG));
        } else {
            record.setEncryptedSequenceNumber(
                    parseByteArrayField(RecordByteLength.DTLS13_CIPHERTEXT_SEQUENCE_NUMBER_SHORT));
        }
        boolean isLengthPresent = (header & 0x04) == 0x04;
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
        // if length is not set, entire rest of the record is protocol message (DTLS 1.3)
        if (record.getLength().getValue() != null) {
            record.setProtocolMessageBytes(parseByteArrayField(record.getLength().getValue()));
        } else {
            record.setProtocolMessageBytes(parseByteArrayField(getBytesLeft()));
        }
        LOGGER.debug("ProtocolMessageBytes: {}", record.getProtocolMessageBytes().getValue());
    }
}
