/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package Modification;

import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.tls.workflow.action.SendAction;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class RemoveMessageModification extends Modification {
    private final ProtocolMessage message;
    private final int position;
    private final SendAction action;

    public RemoveMessageModification(ProtocolMessage message, SendAction action, int position) {
	super(ModificationType.REMOVE_MESSAGE);
	this.message = message;
	this.position = position;
	this.action = action;
    }

    public int getPosition() {
	return position;
    }

    public SendAction getAction() {
	return action;
    }

    public ProtocolMessage getMessage() {
	return message;
    }

}
