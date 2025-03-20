/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.preparator.packet;

import de.rub.nds.tlsattacker.core.quic.packet.LongHeaderPacket;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class LongHeaderPacketPreparator<T extends LongHeaderPacket>
        extends QuicPacketPreparator<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    public LongHeaderPacketPreparator(Chooser chooser, T packet) {
        super(chooser, packet);
    }

    protected void prepareLongHeaderPacket() {
        prepareQuicVersion();
        prepareSourceConnectionId();
        prepareSourceConnectionIdLength();
        prepareQuicPacket();
    }

    protected void prepareSourceConnectionIdLength() {
        packet.setSourceConnectionIdLength((byte) packet.getSourceConnectionId().getValue().length);
        LOGGER.debug(
                "Source Connection ID Length: {}", packet.getSourceConnectionIdLength().getValue());
    }

    protected void prepareSourceConnectionId() {
        packet.setSourceConnectionId(context.getSourceConnectionId());
        LOGGER.debug("Source Connection ID: {}", packet.getSourceConnectionId().getValue());
    }

    public void prepareQuicVersion() {
        packet.setQuicVersion(context.getQuicVersion());
        LOGGER.debug("Quic Version: {}", packet.getQuicVersion().getValue());
    }
}
