/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.serializer.frame;

import de.rub.nds.tlsattacker.core.quic.constants.QuicFrameType;
import de.rub.nds.tlsattacker.core.quic.frame.DatagramFrame;
import de.rub.nds.tlsattacker.core.quic.util.VariableLengthIntegerEncoding;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DatagramFrameSerializer extends QuicFrameSerializer<DatagramFrame> {

    private static final Logger LOGGER = LogManager.getLogger();

    public DatagramFrameSerializer(DatagramFrame frame) {
        super(frame);
    }

    @Override
    protected byte[] serializeBytes() {
        writeFrameType();
        QuicFrameType frameType = QuicFrameType.getFrameType(frame.getFrameType().getValue());
        if (frameType == QuicFrameType.DATAGRAM_FRAME_LEN) {
            writeLength();
        }
        writeData();
        return getAlreadySerialized();
    }

    private void writeLength() {
        appendBytes(
                VariableLengthIntegerEncoding.encodeVariableLengthInteger(
                        frame.getLength().getValue()));
        LOGGER.debug("Length: {}", frame.getLength().getValue());
    }

    private void writeData() {
        appendBytes(frame.getData().getValue());
        LOGGER.debug("Data: {}", frame.getData().getValue());
    }
}
