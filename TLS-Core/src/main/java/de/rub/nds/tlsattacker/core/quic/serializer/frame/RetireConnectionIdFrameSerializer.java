/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.serializer.frame;

import de.rub.nds.tlsattacker.core.quic.frame.RetireConnectionIdFrame;
import de.rub.nds.tlsattacker.core.quic.util.VariableLengthIntegerEncoding;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class RetireConnectionIdFrameSerializer
        extends QuicFrameSerializer<RetireConnectionIdFrame> {

    private static final Logger LOGGER = LogManager.getLogger();

    public RetireConnectionIdFrameSerializer(RetireConnectionIdFrame frame) {
        super(frame);
    }

    @Override
    protected byte[] serializeBytes() {
        writeFrameType();
        writeSequenceNumber();
        return getAlreadySerialized();
    }

    private void writeSequenceNumber() {
        appendBytes(
                VariableLengthIntegerEncoding.encodeVariableLengthInteger(
                        frame.getSequenceNumber().getValue()));
        LOGGER.debug("Sequence Number: {}", frame.getSequenceNumber().getValue());
    }
}
