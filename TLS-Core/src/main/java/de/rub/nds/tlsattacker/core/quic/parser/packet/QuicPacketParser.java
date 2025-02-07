/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.parser.packet;

import de.rub.nds.tlsattacker.core.layer.data.Parser;
import de.rub.nds.tlsattacker.core.quic.constants.QuicPacketByteLength;
import de.rub.nds.tlsattacker.core.quic.packet.QuicPacket;
import de.rub.nds.tlsattacker.core.state.quic.QuicContext;
import java.io.IOException;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class QuicPacketParser<T extends QuicPacket> extends Parser<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    protected QuicContext context;

    public QuicPacketParser(InputStream stream, QuicContext context) {
        super(stream);
        this.context = context;
    }

    protected void parseFlag(T packet) {
        byte firstHeaderByte = parseByteField(QuicPacketByteLength.QUIC_FIRST_HEADER_BYTE);
        packet.protectedHeaderHelper.write(firstHeaderByte);
        packet.setProtectedFlags(firstHeaderByte);
        LOGGER.debug("Protected Flags: {}", packet.getProtectedFlags().getValue());
    }

    protected void parseDestinationConnectionIdLength(T packet) {
        byte destinationConnectionIdBytes =
                parseByteField(QuicPacketByteLength.DESTINATION_CONNECTION_ID_LENGTH);
        packet.protectedHeaderHelper.write(destinationConnectionIdBytes);
        packet.setDestinationConnectionIdLength(destinationConnectionIdBytes);
        LOGGER.debug(
                "Destination Connection ID Length: {}",
                packet.getDestinationConnectionIdLength().getValue());
    }

    protected void parseDestinationConnectionId(T packet) {
        byte[] destinationConnectionIdLengthBytes =
                parseByteArrayField(packet.getDestinationConnectionIdLength().getValue() & 0xFF);
        packet.setDestinationConnectionId(destinationConnectionIdLengthBytes);
        try {
            packet.protectedHeaderHelper.write(destinationConnectionIdLengthBytes);
        } catch (IOException e) {
            e.printStackTrace();
        }
        LOGGER.debug(
                "Destination Connection ID: {}", packet.getDestinationConnectionId().getValue());
    }

    protected void parsePacketLength(T packet) {
        try {
            int before = getStream().available();
            int result = (int) parseVariableLengthInteger();
            int after = getStream().available();
            packet.protectedHeaderHelper.write(quicBuffer.toByteArray());
            quicBuffer.reset();
            packet.setPacketLength(result);
            packet.setPacketLengthSize(before - after);
        } catch (IOException e) {
            e.printStackTrace();
        }
        LOGGER.debug("Packet Length: {}", packet.getPacketLength().getValue());
    }

    protected void parseProtectedPacketNumberAndPayload(T packet) {
        byte[] r = parseByteArrayField(packet.getPacketLength().getValue());
        packet.setProtectedPacketNumberAndPayload(r);
        LOGGER.debug(
                "Protected Packet Number And Payload: {}",
                packet.getProtectedPacketNumberAndPayload().getValue());
    }

    public void parseUnprotectedPacketNumberLength(T packet) {
        byte unprotectedFlags = packet.getUnprotectedFlags().getValue();
        int length = (unprotectedFlags & 0x03) + 1;
        packet.setPacketNumberLength(length);
        LOGGER.debug("Packet Number Length: {}", packet.getPacketNumberLength().getValue());
    }

    public void parseProtectedPacketNumber(T packet) {
        int length = packet.getPacketNumberLength().getValue();
        byte[] packetNumber = new byte[length];
        System.arraycopy(
                packet.getProtectedPacketNumberAndPayload().getValue(), 0, packetNumber, 0, length);
        packet.setProtectedPacketNumber(packetNumber);
        LOGGER.debug("Protected Packet Number: {}", packet.getProtectedPacketNumber().getValue());
    }
}
