/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol;

import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class RetransmitMessageHandler extends ProtocolMessageHandler<RetransmitMessage> {

    private static final Logger LOGGER = LogManager.getLogger(RetransmitMessageHandler.class);

    public RetransmitMessageHandler(TlsContext tlsContext) {
        super(tlsContext);
        this.correctProtocolMessageClass = RetransmitMessage.class;
    }

    /**
     * @param message
     * @param pointer
     * @return
     */
    @Override
    public int parseMessageAction(byte[] message, int pointer) {
        throw new UnsupportedOperationException("Retransmit messages cannot be received");

    }

    @Override
    public byte[] prepareMessageAction() {
        return protocolMessage.getCompleteResultingMessage().getValue();
    }
}
