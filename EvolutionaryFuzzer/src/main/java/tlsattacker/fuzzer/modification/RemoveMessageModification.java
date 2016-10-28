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
import java.util.logging.Logger;

/**
 * A modification which indicates that a message was removed to a WorkflowTrace
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class RemoveMessageModification extends Modification {

    /**
     * The ProtocolMessage that was removed
     */
    private final ProtocolMessage message;

    /**
     * The position of the Message that was removed
     */
    private final int position;

    /**
     * The SendAction from which the Message was removed
     */
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

    private static final Logger LOG = Logger.getLogger(RemoveMessageModification.class.getName());

}
