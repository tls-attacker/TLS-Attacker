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
import de.rub.nds.tlsattacker.core.quic.frame.CryptoFrame;

public class CryptoFrameSerializer extends QuicFrameSerializer<CryptoFrame> {

    public CryptoFrameSerializer(CryptoFrame frame) {
        super(frame);
    }

    @Override
    protected byte[] serializeBytes() {
        writeFrameType();
        writeFrameOffset();
        writeFrameLength();
        writeFrameCryptoData();
        return getAlreadySerialized();
    }

    protected void writeFrameOffset() {
        appendBytes(
                VariableLengthIntegerEncoding.encodeVariableLengthInteger(
                        frame.getOffset().getValue()));
    }

    protected void writeFrameCryptoData() {
        appendBytes(frame.getCryptoData().getValue());
    }

    protected void writeFrameLength() {
        appendBytes(
                VariableLengthIntegerEncoding.encodeVariableLengthInteger(
                        frame.getLength().getValue()));
    }
}
