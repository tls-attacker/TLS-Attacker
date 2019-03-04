/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class AlertPreparator extends ProtocolMessagePreparator<AlertMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final AlertMessage msg;

    public AlertPreparator(Chooser chooser, AlertMessage message) {
        super(chooser, message);
        this.msg = message;
    }

    @Override
    protected void prepareProtocolMessageContents() {
        LOGGER.debug("Preparing AlertMessage");
        prepareLevel(msg);
        prepareDescription(msg);
    }

    private void prepareLevel(AlertMessage msg) {
        if (msg.getConfig() != null && msg.getConfig().length > 0) {
            msg.setLevel(msg.getConfig()[0]);
        } else {
            msg.setLevel(chooser.getConfig().getDefaultAlertLevel());
        }
        LOGGER.debug("Level: " + msg.getLevel().getValue());
    }

    private void prepareDescription(AlertMessage msg) {
        if (msg.getConfig() != null && msg.getConfig().length > 1) {
            msg.setDescription(msg.getConfig()[1]);
        } else {
            msg.setDescription(chooser.getConfig().getDefaultAlertDescription());
        }
        LOGGER.debug("Description: " + msg.getDescription().getValue());
    }

}
