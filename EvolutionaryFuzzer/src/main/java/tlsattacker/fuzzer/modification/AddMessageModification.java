/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.modification;

import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.tls.workflow.action.SendAction;

/**
 * A modification which indicates that a new Message was added to a SendAction
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class AddMessageModification extends Modification {

    /**
     *
     */
    private final ProtocolMessage message;

    /**
     *
     */
    private final SendAction action;

    /**
     *
     * @param message
     * @param action
     */
    public AddMessageModification(ProtocolMessage message, SendAction action) {
	super(ModificationType.ADD_MESSAGE);
	this.message = message;
	this.action = action;
    }

    /**
     *
     * @return
     */
    public ProtocolMessage getMessage() {
	return message;
    }

}
