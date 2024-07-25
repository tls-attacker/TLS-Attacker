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
import de.rub.nds.tlsattacker.core.quic.frame.AckFrame;
import de.rub.nds.tlsattacker.core.quic.frame.AckFrameWithEcn;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class AckFrameSerializer extends QuicFrameSerializer<AckFrame> {

    private static final Logger LOGGER = LogManager.getLogger();

    public AckFrameSerializer(AckFrame frame) {
        super(frame);
    }

    @Override
    protected byte[] serializeBytes() {
        writeFrameType();
        writeLargestAcknowledged();
        writeAckDelay();
        writeAckRangeCount();
        writeFirstAckRange();
        if (frame instanceof AckFrameWithEcn) {
            writeEcn();
        }
        return getAlreadySerialized();
    }

    private void writeLargestAcknowledged() {
        appendBytes(
                VariableLengthIntegerEncoding.encodeVariableLengthInteger(
                        frame.getLargestAcknowledged().getValue()));
        LOGGER.debug("Largest Acknowledged: {}", frame.getLargestAcknowledged().getValue());
    }

    private void writeAckDelay() {
        appendBytes(
                VariableLengthIntegerEncoding.encodeVariableLengthInteger(
                        frame.getAckDelay().getValue()));
        LOGGER.debug("ACK Delay: {}", frame.getAckDelay().getValue());
    }

    private void writeAckRangeCount() {
        appendBytes(
                VariableLengthIntegerEncoding.encodeVariableLengthInteger(
                        frame.getAckRangeCount().getValue()));
        LOGGER.debug("ACK Range Count: {}", frame.getAckRangeCount().getValue());
    }

    private void writeFirstAckRange() {
        appendBytes(
                VariableLengthIntegerEncoding.encodeVariableLengthInteger(
                        frame.getFirstACKRange().getValue()));
        LOGGER.debug("First ACK Range: {}", frame.getFirstACKRange().getValue());
    }

    private void writeEcn() {
        AckFrameWithEcn frameEcn = (AckFrameWithEcn) frame;
        appendBytes(
                VariableLengthIntegerEncoding.encodeVariableLengthInteger(
                        frameEcn.getEct0().getValue()));
        LOGGER.debug("ECT0 Count: {}", frameEcn.getEct0().getValue());
        appendBytes(
                VariableLengthIntegerEncoding.encodeVariableLengthInteger(
                        frameEcn.getEct1().getValue()));
        LOGGER.debug("ECT1 Count: {}", frameEcn.getEct1().getValue());
        appendBytes(
                VariableLengthIntegerEncoding.encodeVariableLengthInteger(
                        frameEcn.getEcnCe().getValue()));
        LOGGER.debug("ECT-CE Count: {}", frameEcn.getEcnCe().getValue());
    }
}
