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

public abstract class QuicPacketParser<T extends QuicPacket<T>> extends Parser<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    protected QuicContext context;

    public QuicPacketParser(InputStream stream, QuicContext context) {
        super(stream);
        this.context = context;
    }

    protected void parseFlag(T message) {
        byte firstHeaderByte = parseByteField(QuicPacketByteLength.QUIC_FIRST_HEADER_BYTE);
        message.protectedHeaderHelper.write(firstHeaderByte);
        message.setProtectedFlags(firstHeaderByte);
    }

    protected void parseDestinationConnectionIdLength(T message) {
        byte destinationConnectionIdBytes =
                parseByteField(QuicPacketByteLength.DESTINATION_CONNECTION_ID_LENGTH);
        message.setDestinationConnectionIdLength(destinationConnectionIdBytes);
        message.protectedHeaderHelper.write(destinationConnectionIdBytes);
    }

    protected void parseDestinationConnectionId(T message) {
        byte[] destinationConnectionIdLengthBytes =
                parseByteArrayField(message.getDestinationConnectionIdLength().getValue());
        message.setDestinationConnectionId(destinationConnectionIdLengthBytes);

        try {
            message.protectedHeaderHelper.write(destinationConnectionIdLengthBytes);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    protected void parsePacketLength(T message) {
        try {
            int before = getStream().available();
            int result = (int) parseVariableLengthInteger();
            int after = getStream().available();
            message.protectedHeaderHelper.write(quicBuffer.toByteArray());
            quicBuffer.reset();
            message.setPacketLength(result);
            message.setPacketLengthSize(before - after);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    protected void parseProtectedPacketNumberAndPayload(T message) {
        byte[] r = parseByteArrayField(message.getPacketLength().getValue());
        message.setProtectedPacketNumberAndPayload(r);
    }

    public void parseUnprotectedPacketNumberLength(T message) {
        byte unprotectedFlags = message.getUnprotectedFlags().getValue();
        int length = (unprotectedFlags & 0x03) + 1;
        message.setPacketNumberLength(length);
    }

    public void parseProtectedPacketNumber(T message) {
        int length = message.getPacketNumberLength().getValue();
        byte[] packetNumber = new byte[length];
        System.arraycopy(
                message.getProtectedPacketNumberAndPayload().getValue(),
                0,
                packetNumber,
                0,
                length);
        message.setProtectedPacketNumber(packetNumber);
    }
}
