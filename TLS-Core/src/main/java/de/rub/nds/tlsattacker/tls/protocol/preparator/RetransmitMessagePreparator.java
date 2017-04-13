/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.preparator;

import de.rub.nds.tlsattacker.tls.protocol.message.RetransmitMessage;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.modifiablevariable.util.ArrayConverter;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class RetransmitMessagePreparator extends ProtocolMessagePreparator<RetransmitMessage> {

    private final RetransmitMessage msg;

    public RetransmitMessagePreparator(TlsContext context, RetransmitMessage message) {
        super(context, message);
        this.msg = message;
    }

    @Override
    protected void prepareProtocolMessageContents() {
        prepareCompleteResultingMessage(msg);
    }

    private void prepareCompleteResultingMessage(RetransmitMessage msg) {
        msg.setCompleteResultingMessage(msg.getBytesToTransmit());
        LOGGER.debug("CompleteResultingMessage: "
                + ArrayConverter.bytesToHexString(msg.getCompleteResultingMessage().getValue()));
    }
}
