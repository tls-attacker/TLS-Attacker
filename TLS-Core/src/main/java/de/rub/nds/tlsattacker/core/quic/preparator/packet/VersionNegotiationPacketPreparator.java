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
import de.rub.nds.tlsattacker.core.quic.constants.QuicVersion;
import de.rub.nds.tlsattacker.core.quic.packet.VersionNegotiationPacket;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class VersionNegotiationPacketPreparator
        extends LongHeaderPacketPreparator<VersionNegotiationPacket> {

    private static final Logger LOGGER = LogManager.getLogger();

    public VersionNegotiationPacketPreparator(Chooser chooser, VersionNegotiationPacket packet) {
        super(chooser, packet);
    }

    @Override
    public void prepare() {
        LOGGER.debug("Preparing Version Negotiation Packet");
        prepareUnprotectedFlags();
        prepareQuicVersion();
        prepareDestinationConnectionId();
        prepareDestinationConnectionIdLength();
        prepareSourceConnectionId();
        prepareSourceConnectionIdLength();
        prepareSupportedVersions();
    }

    private void prepareSupportedVersions() {
        packet.setSupportedVersions(context.getConfig().getQuicVersion().getByteValue());
        LOGGER.debug("Supported Versions: {}", packet.getSupportedVersions().getValue());
    }

    @Override
    public void prepareQuicVersion() {
        packet.setQuicVersion(QuicVersion.NULL_VERSION);
        LOGGER.debug("Quic Version: {}", packet.getQuicVersion().getValue());
    }

    private void prepareUnprotectedFlags() {
        packet.setUnprotectedFlags(
                QuicPacketType.VERSION_NEGOTIATION.getHeader(context.getQuicVersion()));
        LOGGER.debug("Unprotected Flags: {}", packet.getUnprotectedFlags().getValue());
    }
}
