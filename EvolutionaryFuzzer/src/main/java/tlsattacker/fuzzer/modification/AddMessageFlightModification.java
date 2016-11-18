/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.modification;

import de.rub.nds.tlsattacker.tls.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.tls.workflow.action.SendAction;
import java.util.logging.Logger;

/**
 * A modification which indicates that new pair of SendAction and ReceiveAction
 * was added to the WorkflowTrace.
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class AddMessageFlightModification extends Modification {

    /**
     * The SendAction that was added
     */
    private final SendAction sendAction;

    /**
     * The ReceiveAction that was added
     */
    private final ReceiveAction receiveAction;

    public AddMessageFlightModification(SendAction sendAction, ReceiveAction receiveAction) {
        super(ModificationType.ADD_MESSAGE_FLIGHT);
        this.sendAction = sendAction;
        this.receiveAction = receiveAction;
    }

    public SendAction getSendAction() {
        return sendAction;
    }

    public ReceiveAction getReceiveAction() {
        return receiveAction;
    }

    private static final Logger LOG = Logger.getLogger(AddMessageFlightModification.class.getName());
}
