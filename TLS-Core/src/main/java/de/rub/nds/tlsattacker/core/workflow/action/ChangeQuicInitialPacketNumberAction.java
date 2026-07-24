/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.state.quic.QuicContext;
import jakarta.xml.bind.annotation.XmlRootElement;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@XmlRootElement
public class ChangeQuicInitialPacketNumberAction extends ChangeQuicPacketNumberAction {

    private static final Logger LOGGER = LogManager.getLogger();

    public ChangeQuicInitialPacketNumberAction() {}

    public ChangeQuicInitialPacketNumberAction(int packetNumber) {
        super(packetNumber);
    }

    @Override
    protected void changePacketNumber(QuicContext quicContext) {
        LOGGER.info("Changed QUIC initial packet number");
        if (quicContext != null) {
            quicContext.setInitialPacketPacketNumber(packetNumber);
        }
    }
}
