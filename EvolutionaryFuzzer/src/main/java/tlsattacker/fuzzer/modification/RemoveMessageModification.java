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
     *
     */
    private final ProtocolMessage message;

    /**
     *
     */
    private final int position;

    /**
     *
     */
    private final SendAction action;

    /**
     * 
     * @param message
     * @param action
     * @param position
     */
    public RemoveMessageModification(ProtocolMessage message, SendAction action, int position) {
	super(ModificationType.REMOVE_MESSAGE);
	this.message = message;
	this.position = position;
	this.action = action;
    }

    /**
     * 
     * @return
     */
    public int getPosition() {
	return position;
    }

    /**
     * 
     * @return
     */
    public SendAction getAction() {
	return action;
    }

    /**
     * 
     * @return
     */
    public ProtocolMessage getMessage() {
	return message;
    }

    private static final Logger LOG = Logger.getLogger(RemoveMessageModification.class.getName());

}
