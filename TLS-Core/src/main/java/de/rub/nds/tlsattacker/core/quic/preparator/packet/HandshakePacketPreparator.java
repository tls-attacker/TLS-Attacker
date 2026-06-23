/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.preparator.packet;

import de.rub.nds.tlsattacker.core.quic.constants.QuicPacketType;
import de.rub.nds.tlsattacker.core.quic.packet.HandshakePacket;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class HandshakePacketPreparator extends LongHeaderPacketPreparator<HandshakePacket> {

    private static final Logger LOGGER = LogManager.getLogger();

    public HandshakePacketPreparator(Chooser chooser, HandshakePacket packet) {
        super(chooser, packet);
    }

    @Override
    public void prepare() {
        LOGGER.debug("Preparing Handshake Packet");
        prepareUnprotectedPacketNumber();
        preparePacketNumberLength();
        prepareUnprotectedFlags();
        prepareLongHeaderPacket();
    }

    private void prepareUnprotectedPacketNumber() {
        if (packet.getUnprotectedPacketNumber() == null) {
            packet.setUnprotectedPacketNumber(context.getHandshakePacketPacketNumber());
            context.setHandshakePacketPacketNumber(context.getHandshakePacketPacketNumber() + 1);
            LOGGER.debug(
                    "Unprotected Packet Number: {}",
                    packet.getUnprotectedPacketNumber().getValue());
        }
    }

    private void prepareUnprotectedFlags() {
        byte packetType = QuicPacketType.HANDSHAKE_PACKET.getHeader(context.getQuicVersion());
        int packetNumber = packet.getPacketNumberLength().getValue();
        packet.setUnprotectedFlags((byte) (packetType ^ (packetNumber - 1)));
        LOGGER.debug("Unprotected Flags: {}", packet.getUnprotectedFlags().getValue());
    }
}
