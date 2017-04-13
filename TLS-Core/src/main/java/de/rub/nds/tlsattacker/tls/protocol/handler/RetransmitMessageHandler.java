/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.handler;

import de.rub.nds.tlsattacker.tls.protocol.message.RetransmitMessage;
import de.rub.nds.tlsattacker.tls.protocol.parser.Parser;
import de.rub.nds.tlsattacker.tls.protocol.parser.ProtocolMessageParser;
import de.rub.nds.tlsattacker.tls.protocol.preparator.Preparator;
import de.rub.nds.tlsattacker.tls.protocol.preparator.RetransmitMessagePreparator;
import de.rub.nds.tlsattacker.tls.protocol.serializer.RetransmitMessageSerializer;
import de.rub.nds.tlsattacker.tls.protocol.serializer.Serializer;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class RetransmitMessageHandler extends ProtocolMessageHandler<RetransmitMessage> {

    public RetransmitMessageHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public ProtocolMessageParser getParser(byte[] message, int pointer) {
        throw new UnsupportedOperationException(
                "Receiving a retransmitted message is impossible, it would appear the correct message in the WorkflowTrace");
    }

    @Override
    public RetransmitMessagePreparator getPreparator(RetransmitMessage message) {
        return new RetransmitMessagePreparator(tlsContext, message);
    }

    @Override
    public RetransmitMessageSerializer getSerializer(RetransmitMessage message) {
        return new RetransmitMessageSerializer(message, tlsContext.getSelectedProtocolVersion());
    }

    @Override
    protected void adjustTLSContext(RetransmitMessage message) {
        // nothing to adjust
    }
}
