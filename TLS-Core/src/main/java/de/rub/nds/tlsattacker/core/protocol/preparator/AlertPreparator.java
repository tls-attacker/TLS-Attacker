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

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class AlertPreparator extends ProtocolMessagePreparator<AlertMessage> {

    private final AlertMessage msg;

    public AlertPreparator(Chooser chooser, AlertMessage message) {
        super(chooser, message);
        this.msg = message;
    }

    @Override
    protected void prepareProtocolMessageContents() {
        prepareLevel(msg);
        prepareDescription(msg);
    }

    private void prepareLevel(AlertMessage msg) {
        msg.setLevel(msg.getConfig()[0]);
        LOGGER.debug("Level: " + msg.getLevel().getValue());
    }

    private void prepareDescription(AlertMessage msg) {
        msg.setDescription(msg.getConfig()[1]);
        LOGGER.debug("Description: " + msg.getDescription().getValue());
    }

}
