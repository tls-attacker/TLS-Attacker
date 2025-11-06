/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.serializer.frame;

import de.rub.nds.tlsattacker.core.quic.frame.StopSendingFrame;
import de.rub.nds.tlsattacker.core.quic.util.VariableLengthIntegerEncoding;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class StopSendingFrameSerializer extends QuicFrameSerializer<StopSendingFrame> {

    private static final Logger LOGGER = LogManager.getLogger();

    public StopSendingFrameSerializer(StopSendingFrame frame) {
        super(frame);
    }

    @Override
    protected byte[] serializeBytes() {
        writeFrameType();
        writeStreamId();
        writeApplicationProtocolErrorCode();
        return getAlreadySerialized();
    }

    private void writeStreamId() {
        appendBytes(
                VariableLengthIntegerEncoding.encodeVariableLengthInteger(
                        frame.getStreamId().getValue()));
        LOGGER.debug("Stream ID: {}", frame.getStreamId().getValue());
    }

    private void writeApplicationProtocolErrorCode() {
        appendBytes(
                VariableLengthIntegerEncoding.encodeVariableLengthInteger(
                        frame.getApplicationProtocolErrorCode().getValue()));
        LOGGER.debug(
                "Application Protocol Error Code: {}",
                frame.getApplicationProtocolErrorCode().getValue());
    }
}
