/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.preparator.packet;

import de.rub.nds.tlsattacker.core.quic.packet.RetryPacket;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

public class RetryPacketPreparator extends LongHeaderPacketPreparator<RetryPacket> {

    public RetryPacketPreparator(Chooser chooser, RetryPacket packet) {
        super(chooser, packet);
    }

    @Override
    public void prepare() {
        // TODO
        throw new UnsupportedOperationException("Not supported yet.");
    }
}
