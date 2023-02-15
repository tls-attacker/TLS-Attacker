/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.record.serializer;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.RecordByteLength;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.layer.data.Serializer;
import de.rub.nds.tlsattacker.core.record.Record;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class RecordSerializer extends Serializer<Record> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final Record record;

    private final TlsContext tlsContext;

    public RecordSerializer(Record record, TlsContext tlsContext) {
        this.record = record;
        this.tlsContext = tlsContext;
    }

    @Override
    protected byte[] serializeBytes() {
        LOGGER.debug("Serializing Record");
        if (tlsContext.getChooser().getSelectedProtocolVersion() == ProtocolVersion.DTLS13
                && record.getEpoch().getValue() > 0) {
            writeDtls13Header(record);
        } else {
            writeContentType(record);
            writeProtocolVersion(record);
            if (record.getEpoch() != null) {
                writeEpoch(record);
                writeSequenceNumber(record);
            }
            if (record.getConnectionId() != null
                    && record.getConnectionId().getValue() != null
                    && record.getConnectionId().getValue().length > 0) {
                writeConnectionId(record);
            }
            writeLength(record);
        }
        writeProtocolMessageBytes(record);
        return getAlreadySerialized();
    }

    public static byte createUnifiedHeader(Record record, TlsContext context) {
        byte firstByte = 0x24; // 00100100 (length field is always present)
        if (record.getConnectionId() != null
                && record.getConnectionId().getValue() != null
                && record.getConnectionId().getValue().length > 0) {
            firstByte = (byte) (firstByte ^ 0x10);
        }
        if (context.getConfig().getDtls13HeaderSeqNumSizeLong()) {
            firstByte = (byte) (firstByte ^ 0x08);
        }
        byte lowerEpoch = (byte) (record.getEpoch().getValue() % 4);
        firstByte = (byte) (firstByte ^ lowerEpoch);
        record.setUnifiedHeader(firstByte);
        return firstByte;
    }

    private void writeDtls13Header(Record record) {
        record.setUnifiedHeader(createUnifiedHeader(record, tlsContext));
        writeUnifiedHeader(record);
        if (record.getConnectionId() != null
                && record.getConnectionId().getValue() != null
                && record.getConnectionId().getValue().length > 0) {
            writeConnectionId(record);
        }
        writeEncryptedSequenceNumber(record);
        writeLength(record);
    }

    private void writeUnifiedHeader(Record record) {
        appendByte(record.getUnifiedHeader().getValue());
        LOGGER.debug(
                "UnifiedHeader: 00" + Integer.toBinaryString(record.getUnifiedHeader().getValue()));
    }

    private void writeEncryptedSequenceNumber(Record record) {
        appendBytes(record.getEncryptedSequenceNumber().getValue());
        LOGGER.debug(
                "Encrypted SequenceNumber: "
                        + ArrayConverter.bytesToHexString(
                                record.getEncryptedSequenceNumber().getValue()));
    }

    private void writeContentType(Record record) {
        appendByte(record.getContentType().getValue());
        LOGGER.debug("ContentType: " + record.getContentType().getValue());
    }

    private void writeProtocolVersion(Record record) {
        appendBytes(record.getProtocolVersion().getValue());
        LOGGER.debug("ProtocolVersion: {}", record.getProtocolVersion().getValue());
    }

    private void writeLength(Record record) {
        appendInt(record.getLength().getValue(), RecordByteLength.RECORD_LENGTH);
        LOGGER.debug("Length: " + record.getLength().getValue());
    }

    private void writeConnectionId(Record record) {
        appendBytes(record.getConnectionId().getValue());
        LOGGER.debug("ConnectionID: {}", record.getConnectionId().getValue());
    }

    private void writeEpoch(Record record) {
        appendInt(record.getEpoch().getValue(), RecordByteLength.DTLS_EPOCH);
        LOGGER.debug("Epoch: " + record.getEpoch().getValue());
    }

    private void writeSequenceNumber(Record record) {
        appendBigInteger(
                record.getSequenceNumber().getValue(), RecordByteLength.DTLS_SEQUENCE_NUMBER);
        LOGGER.debug("SequenceNumber: " + record.getSequenceNumber().getValue());
    }

    private void writeProtocolMessageBytes(Record record) {
        appendBytes(record.getProtocolMessageBytes().getValue());
        LOGGER.debug("ProtocolMessageBytes: {}", record.getProtocolMessageBytes().getValue());
    }
}
