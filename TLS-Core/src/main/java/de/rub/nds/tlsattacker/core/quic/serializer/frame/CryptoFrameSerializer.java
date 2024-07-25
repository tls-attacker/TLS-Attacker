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
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class CryptoFrameSerializer extends QuicFrameSerializer<CryptoFrame> {

    private static final Logger LOGGER = LogManager.getLogger();

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
        LOGGER.debug("Offset: {}", frame.getOffset().getValue());
    }

    protected void writeFrameCryptoData() {
        appendBytes(frame.getCryptoData().getValue());
        LOGGER.debug("Length: {}", frame.getLength().getValue());
    }

    protected void writeFrameLength() {
        appendBytes(
                VariableLengthIntegerEncoding.encodeVariableLengthInteger(
                        frame.getLength().getValue()));
        LOGGER.debug("Crypto Data: {}", frame.getCryptoData().getValue());
    }
}
