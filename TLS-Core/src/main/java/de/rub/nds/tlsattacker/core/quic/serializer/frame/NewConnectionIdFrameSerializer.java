/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.serializer.frame;

import de.rub.nds.tlsattacker.core.quic.frame.NewConnectionIdFrame;
import de.rub.nds.tlsattacker.core.quic.util.VariableLengthIntegerEncoding;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class NewConnectionIdFrameSerializer extends QuicFrameSerializer<NewConnectionIdFrame> {

    private static final Logger LOGGER = LogManager.getLogger();

    public NewConnectionIdFrameSerializer(NewConnectionIdFrame frame) {
        super(frame);
    }

    @Override
    protected byte[] serializeBytes() {
        writeFrameType();
        writeSequenceNumber();
        writeRetirePriorTo();
        writeConnectionIdLength();
        writeConnectionId();
        writeStatelessResetToken();
        return getAlreadySerialized();
    }

    protected void writeSequenceNumber() {
        appendBytes(
                VariableLengthIntegerEncoding.encodeVariableLengthInteger(
                        frame.getSequenceNumber().getValue()));
        LOGGER.debug("Sequence  Number: {}", frame.getSequenceNumber().getValue());
    }

    protected void writeRetirePriorTo() {
        appendBytes(
                VariableLengthIntegerEncoding.encodeVariableLengthInteger(
                        frame.getRetirePriorTo().getValue()));
        LOGGER.debug("Retire Prior To: {}", frame.getRetirePriorTo().getValue());
    }

    protected void writeConnectionIdLength() {
        if (frame.getConnectionIdLength().getValue() > 255) {
            LOGGER.warn(
                    "Connection ID length exceeds maximum length encodable in NEW_CONNECTION_ID frame.");
        }
        appendInt(
                frame.getConnectionIdLength().getValue(),
                NewConnectionIdFrame.CONNECTION_ID_LENGTH_FIELD_LENGTH);
        LOGGER.debug("Length: {}", frame.getConnectionIdLength().getValue());
    }

    protected void writeConnectionId() {
        appendBytes(frame.getConnectionId().getValue());
        LOGGER.debug("Connection ID: {}", frame.getConnectionId().getValue());
    }

    protected void writeStatelessResetToken() {
        appendBytes(frame.getStatelessResetToken().getValue());
        LOGGER.debug("Stateless Reset Token: {}", frame.getStatelessResetToken().getValue());
    }
}
