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
 * A modification which indicates that a message was duplicated in the
 * WorkflowTrace
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class DuplicateMessageModification extends Modification {

    /**
     * The ProtocolMessage that was duplicated
     */
    private final ProtocolMessage message;

    /**
     * The position to which the duplicate was pasted
     */
    private final int position;

    /**
     * The Action in which the duplication appeared
     */
    private final SendAction action;

    public DuplicateMessageModification(ProtocolMessage message, SendAction action, int position) {
        super(ModificationType.DUPLICATE_MESSAGE);
        this.message = message;
        this.position = position;
        this.action = action;
    }

    public SendAction getAction() {
        return action;
    }

    public int getPosition() {
        return position;
    }

    public ProtocolMessage getMessage() {
        return message;
    }

    private static final Logger LOG = Logger.getLogger(DuplicateMessageModification.class.getName());
}
