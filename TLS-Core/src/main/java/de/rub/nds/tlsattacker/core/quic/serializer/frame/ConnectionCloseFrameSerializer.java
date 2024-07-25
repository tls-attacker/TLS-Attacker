/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.serializer.frame;

import de.rub.nds.tlsattacker.core.quic.VariableLengthIntegerEncoding;
import de.rub.nds.tlsattacker.core.quic.frame.ConnectionCloseFrame;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ConnectionCloseFrameSerializer extends QuicFrameSerializer<ConnectionCloseFrame> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ConnectionCloseFrameSerializer(ConnectionCloseFrame frame) {
        super(frame);
    }

    @Override
    protected byte[] serializeBytes() {
        writeFrameType();
        writeErrorCode();
        writeTriggerFrameType();
        writeReasonPhraseLength();
        writeReasonPhrase();
        return getAlreadySerialized();
    }

    private void writeErrorCode() {
        appendBytes(
                VariableLengthIntegerEncoding.encodeVariableLengthInteger(
                        frame.getErrorCode().getValue()));
        LOGGER.debug("Error Code: {}", frame.getErrorCode().getValue());
    }

    private void writeTriggerFrameType() {
        appendBytes(
                VariableLengthIntegerEncoding.encodeVariableLengthInteger(
                        frame.getTriggerFrameType().getValue()));
        LOGGER.debug("Frame Type: {}", frame.getTriggerFrameType().getValue());
    }

    private void writeReasonPhraseLength() {
        if (frame.getReasonPhraseLength() != null) {
            appendBytes(
                    VariableLengthIntegerEncoding.encodeVariableLengthInteger(
                            frame.getReasonPhraseLength().getValue()));
            LOGGER.debug("Reason Phrase Length: {}", frame.getReasonPhraseLength().getValue());
        }
    }

    private void writeReasonPhrase() {
        if (frame.getReasonPhrase() != null) {
            appendBytes(frame.getReasonPhrase().getValue());
            LOGGER.debug("Reason Phrase: {}", frame.getReasonPhrase().getValue());
        }
    }
}
