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

public abstract class LongHeaderPacketPreparator<T extends LongHeaderPacket>
        extends QuicPacketPreparator<T> {

    public LongHeaderPacketPreparator(Chooser chooser, T packet) {
        super(chooser, packet);
        this.packet = packet;
    }

    protected void prepareLongHeaderPacket() {
        packet.setQuicVersion(context.getQuicVersion());
        packet.setSourceConnectionId(context.getSourceConnectionId());
        packet.setSourceConnectionIdLength((byte) packet.getSourceConnectionId().getValue().length);
        prepareQuicPacket();
    }
}
