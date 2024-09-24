/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.serializer.frame;

import de.rub.nds.tlsattacker.core.quic.frame.ResetStreamFrame;
import de.rub.nds.tlsattacker.core.quic.util.VariableLengthIntegerEncoding;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ResetStreamFrameSerializer extends QuicFrameSerializer<ResetStreamFrame> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ResetStreamFrameSerializer(ResetStreamFrame frame) {
        super(frame);
    }

    @Override
    protected byte[] serializeBytes() {
        writeFrameType();
        writeStreamId();
        writeApplicationProtocolErrorCode();
        writeFinalSize();
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

    protected void writeFinalSize() {
        appendBytes(
                VariableLengthIntegerEncoding.encodeVariableLengthInteger(
                        frame.getFinalSize().getValue()));
        LOGGER.debug("Final Size: {}", frame.getFinalSize().getValue());
    }
}
