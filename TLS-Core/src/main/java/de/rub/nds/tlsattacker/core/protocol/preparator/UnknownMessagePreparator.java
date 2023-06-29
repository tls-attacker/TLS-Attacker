/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.tlsattacker.core.protocol.ProtocolMessagePreparator;
import de.rub.nds.tlsattacker.core.protocol.message.UnknownMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class UnknownMessagePreparator extends ProtocolMessagePreparator<UnknownMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final UnknownMessage msg;

    public UnknownMessagePreparator(Chooser chooser, UnknownMessage message) {
        super(chooser, message);
        this.msg = message;
    }

    @Override
    protected void prepareProtocolMessageContents() {
        LOGGER.debug("Preparing UnknownMessage");
        prepareCompleteResultingMessage(msg);
    }

    private void prepareCompleteResultingMessage(UnknownMessage msg) {
        if (msg.getDataConfig() != null) {
            msg.setCompleteResultingMessage(msg.getDataConfig());
        } else {
            msg.setCompleteResultingMessage(new byte[0]);
        }
        LOGGER.debug("CompleteResultingMessage: {}", msg.getCompleteResultingMessage().getValue());
    }
}
