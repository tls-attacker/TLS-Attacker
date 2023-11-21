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

public class ConnectionCloseFrameSerializer extends QuicFrameSerializer {

    private final ConnectionCloseFrame frame;

    public ConnectionCloseFrameSerializer(ConnectionCloseFrame frame) {
        super(frame);
        this.frame = frame;
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
    }

    private void writeTriggerFrameType() {
        appendBytes(
                VariableLengthIntegerEncoding.encodeVariableLengthInteger(
                        frame.getTriggerFrameType().getValue()));
    }

    private void writeReasonPhraseLength() {
        appendBytes(
                VariableLengthIntegerEncoding.encodeVariableLengthInteger(
                        frame.getReasonPhraseLength().getValue()));
    }

    private void writeReasonPhrase() {
        if (frame.getReasonPhrase() != null) {
            appendBytes(frame.getReasonPhrase().getValue());
        }
    }
}
