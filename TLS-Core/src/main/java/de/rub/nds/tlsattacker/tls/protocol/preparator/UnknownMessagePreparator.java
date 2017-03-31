/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.preparator;

import de.rub.nds.tlsattacker.tls.protocol.message.UnknownMessage;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class UnknownMessagePreparator extends ProtocolMessagePreparator<UnknownMessage> {

    private static final Logger LOGGER = LogManager.getLogger("PREPARATOR");

    private final UnknownMessage msg;

    public UnknownMessagePreparator(TlsContext context, UnknownMessage message) {
        super(context, message);
        this.msg = message;
    }

    @Override
    protected void prepareProtocolMessageContents() {
        prepareCompleteResultingMessage(msg);
    }

    private void prepareCompleteResultingMessage(UnknownMessage msg) {
        msg.setCompleteResultingMessage(msg.getDataConfig());
        LOGGER.debug("CompleteResultinMessage: "+ Arrays.toString(msg.getCompleteResultingMessage().getValue()));
    }

}
