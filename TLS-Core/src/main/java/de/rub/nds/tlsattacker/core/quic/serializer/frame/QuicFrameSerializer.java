/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.serializer.frame;

import de.rub.nds.tlsattacker.core.layer.data.Serializer;
import de.rub.nds.tlsattacker.core.quic.VariableLengthIntegerEncoding;
import de.rub.nds.tlsattacker.core.quic.frame.QuicFrame;

public abstract class QuicFrameSerializer<T extends QuicFrame<T>> extends Serializer<T> {

    protected final T frame;

    public QuicFrameSerializer(T frame) {
        this.frame = frame;
    }

    @Override
    protected byte[] serializeBytes() {
        writeFrameType();
        return getAlreadySerialized();
    }

    protected void writeFrameType() {
        appendBytes(
                VariableLengthIntegerEncoding.encodeVariableLengthInteger(
                        frame.getFrameType().getValue()));
    }
}
