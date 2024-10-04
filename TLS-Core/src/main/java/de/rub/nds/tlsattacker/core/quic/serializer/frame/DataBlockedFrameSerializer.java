/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.serializer.frame;

import de.rub.nds.tlsattacker.core.quic.frame.DataBlockedFrame;
import de.rub.nds.tlsattacker.core.quic.util.VariableLengthIntegerEncoding;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DataBlockedFrameSerializer extends QuicFrameSerializer<DataBlockedFrame> {

    private static final Logger LOGGER = LogManager.getLogger();

    public DataBlockedFrameSerializer(DataBlockedFrame frame) {
        super(frame);
    }

    @Override
    protected byte[] serializeBytes() {
        writeFrameType();
        writeMaximumData();
        return getAlreadySerialized();
    }

    private void writeMaximumData() {
        appendBytes(
                VariableLengthIntegerEncoding.encodeVariableLengthInteger(
                        frame.getMaximumData().getValue()));
        LOGGER.debug("Maximum Data: {}", frame.getMaximumData().getValue());
    }
}
