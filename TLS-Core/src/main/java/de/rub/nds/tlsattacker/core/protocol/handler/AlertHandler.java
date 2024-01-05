/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.constants.AlertLevel;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class AlertHandler extends ProtocolMessageHandler<AlertMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public AlertHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public void adjustContext(AlertMessage message) {
        if (tlsContext.getTalkingConnectionEndType()
                        == tlsContext.getChooser().getMyConnectionPeer()
                && AlertLevel.FATAL.getValue() == message.getLevel().getValue()) {
            LOGGER.debug("Setting received Fatal Alert in Context");
            tlsContext.setReceivedFatalAlert(true);
        }
    }
}
