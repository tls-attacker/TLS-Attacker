/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.protocol.message.RetransmitMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

public class RetransmitMessagePreparator extends ProtocolMessagePreparator<RetransmitMessage> {

    private final RetransmitMessage msg;

    public RetransmitMessagePreparator(Chooser chooser, RetransmitMessage message) {
        super(chooser, message);
        this.msg = message;
    }

    @Override
    protected void prepareProtocolMessageContents() {
        LOGGER.debug("Preparing RetransmitMessage");
        prepareCompleteResultingMessage(msg);
    }

    private void prepareCompleteResultingMessage(RetransmitMessage msg) {
        msg.setCompleteResultingMessage(msg.getBytesToTransmit());
        LOGGER.debug("CompleteResultingMessage: "
                + ArrayConverter.bytesToHexString(msg.getCompleteResultingMessage().getValue()));
    }
}
