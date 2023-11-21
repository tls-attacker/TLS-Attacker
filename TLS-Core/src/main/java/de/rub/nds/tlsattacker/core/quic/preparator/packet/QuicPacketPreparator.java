/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.preparator.packet;

import de.rub.nds.tlsattacker.core.layer.data.Preparator;
import de.rub.nds.tlsattacker.core.quic.constants.MiscCustomConstants;
import de.rub.nds.tlsattacker.core.quic.constants.MiscRfcConstants;
import de.rub.nds.tlsattacker.core.quic.packet.QuicPacket;
import de.rub.nds.tlsattacker.core.state.quic.QuicContext;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class QuicPacketPreparator<T extends QuicPacket> extends Preparator<T> {

    protected QuicContext context;
    protected T packet;

    private static final Logger LOGGER = LogManager.getLogger();

    public QuicPacketPreparator(Chooser chooser, T packet) {
        super(chooser, packet);
        context = chooser.getContext().getQuicContext();
    }

    protected void prepareQuicPacket() {
        packet.setDestinationConnectionId(context.getDestinationConnectionId());

        packet.setDestinationConnectionIdLength(
                (byte) packet.getDestinationConnectionId().getValue().length);

        packet.setPacketNumberLength(packet.getUnprotectedPacketNumber().getValue().length);

        if (packet.getPadding() == 0) {
            packet.setPadding(calculatePadding());
        }

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        try {
            outputStream.write(packet.getUnprotectedPayload().getValue());
            if (packet.getPadding() > 0) {
                outputStream.write(new byte[packet.getPadding()]);
            }
        } catch (IOException e) {
            LOGGER.error(e);
        }
        packet.setUnprotectedPayload(outputStream.toByteArray());

        packet.setPacketLength(
                packet.getUnprotectedPayload().getValue().length
                        + packet.getPacketNumberLength().getValue()
                        + MiscRfcConstants.AUTH_TAG_LENGTH);
        packet.buildUnprotectedPacketHeader();
    }

    protected int calculatePadding() {
        return Math.max(
                0,
                MiscCustomConstants.MIN_PACKET_CONTENT_SIZE
                        - packet.getUnprotectedPayload().getValue().length);
    }
}
