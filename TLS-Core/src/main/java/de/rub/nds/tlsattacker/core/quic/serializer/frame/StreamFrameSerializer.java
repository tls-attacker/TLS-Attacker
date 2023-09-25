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
import de.rub.nds.tlsattacker.core.quic.frame.StreamFrame;

public class StreamFrameSerializer extends QuicFrameSerializer<StreamFrame> {

    public StreamFrameSerializer(StreamFrame frame) {
        super(frame);
    }

    @Override
    protected byte[] serializeBytes() {
        writeFrameType();
        writeStreamId();
        if (frame.getOffset() != null) {
            writeOffset();
        }
        if (frame.getLength() != null) {
            writeLength();
        }
        writeData();
        return getAlreadySerialized();
    }

    protected void writeStreamId() {
        appendBytes(
                VariableLengthIntegerEncoding.encodeVariableLengthInteger(
                        frame.getStreamId().getValue()));
    }

    protected void writeOffset() {
        appendBytes(
                VariableLengthIntegerEncoding.encodeVariableLengthInteger(
                        frame.getOffset().getValue()));
    }

    protected void writeLength() {
        appendBytes(
                VariableLengthIntegerEncoding.encodeVariableLengthInteger(
                        frame.getLength().getValue()));
    }

    protected void writeData() {
        appendBytes(frame.getData().getValue());
    }
}
