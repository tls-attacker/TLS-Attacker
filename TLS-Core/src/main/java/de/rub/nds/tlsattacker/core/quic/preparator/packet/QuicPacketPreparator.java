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

    private static final Logger LOGGER = LogManager.getLogger();

    protected QuicContext context;
    protected T packet;

    public QuicPacketPreparator(Chooser chooser, T packet) {
        super(chooser, packet);
        this.packet = packet;
        this.context = chooser.getContext().getQuicContext();
    }

    protected void prepareQuicPacket() {
        prepareDestinationConnectionId();
        prepareDestinationConnectionIdLength();
        preparePacketNumberLength();
        preparePadding();
        prepareUnprotectedPayload();
        preparePacketLength();
        packet.buildUnprotectedPacketHeader();
    }

    private void preparePacketLength() {
        packet.setPacketLength(
                packet.getUnprotectedPayload().getValue().length
                        + packet.getPacketNumberLength().getValue()
                        + MiscRfcConstants.AUTH_TAG_LENGTH);
        LOGGER.debug("Packet Length: {}", packet.getPacketLength().getValue());
    }

    private void prepareUnprotectedPayload() {
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
        LOGGER.debug("Unprotected Payload: {}", packet.getUnprotectedPayload().getValue());
    }

    private void prepareDestinationConnectionId() {
        packet.setDestinationConnectionId(context.getDestinationConnectionId());
        LOGGER.debug(
                "Destination Connection ID: {}", packet.getDestinationConnectionId().getValue());
    }

    private void prepareDestinationConnectionIdLength() {
        packet.setDestinationConnectionIdLength(
                (byte) packet.getDestinationConnectionId().getValue().length);
        LOGGER.debug(
                "Destination Connection ID Length: {}",
                packet.getDestinationConnectionIdLength().getValue());
    }

    private void preparePacketNumberLength() {
        packet.setPacketNumberLength(packet.getUnprotectedPacketNumber().getValue().length);
        LOGGER.debug("Packet Number Length: {}", packet.getPacketNumberLength().getValue());
    }

    private void preparePadding() {
        if (packet.getPadding() == 0) {
            packet.setPadding(calculatePadding());
            LOGGER.debug("Padding: {}", packet.getPadding());
        }
    }

    protected int calculatePadding() {
        if (packet.getConfiguredPadding() > -1) {
            return packet.getConfiguredPadding();
        }
        if (context.getConfig().isQuicDoNotPad()) {
            return 0;
        }
        return Math.max(
                0,
                MiscCustomConstants.MIN_PACKET_CONTENT_SIZE
                        - packet.getUnprotectedPayload().getValue().length);
    }
}
