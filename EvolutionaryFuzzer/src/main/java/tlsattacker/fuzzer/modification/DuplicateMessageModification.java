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
 * A modification which indicates that a message was duplicated in the WorkflowTrace
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class DuplicateMessageModification extends Modification {

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
    public DuplicateMessageModification(ProtocolMessage message, SendAction action, int position) {
	super(ModificationType.DUPLICATE_MESSAGE);
	this.message = message;
	this.position = position;
	this.action = action;
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
    public int getPosition() {
	return position;
    }

    /**
     *
     * @return
     */
    public ProtocolMessage getMessage() {
	return message;
    }

}
