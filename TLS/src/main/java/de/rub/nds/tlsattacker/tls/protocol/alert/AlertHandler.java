/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.alert;

import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class AlertHandler extends ProtocolMessageHandler<AlertMessage> {

    public AlertHandler(TlsContext tlsContext) {
	super(tlsContext);
	this.correctProtocolMessageClass = AlertMessage.class;
    }

    @Override
    public byte[] prepareMessageAction() {
	protocolMessage.setLevel(protocolMessage.getConfig()[0]);
	protocolMessage.setDescription(protocolMessage.getConfig()[1]);
	byte[] result = { protocolMessage.getLevel().getValue(), protocolMessage.getDescription().getValue() };
	protocolMessage.setCompleteResultingMessage(result);
	return result;
    }

    @Override
    public int parseMessageAction(byte[] message, int pointer) {
	protocolMessage.setLevel(message[pointer]);
	protocolMessage.setDescription(message[pointer + 1]);
	return (pointer + 2);
    }
}
