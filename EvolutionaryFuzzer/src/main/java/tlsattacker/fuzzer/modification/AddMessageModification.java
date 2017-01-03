/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
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
     * The ProtocolMessage that was added
     */
    private final ProtocolMessage message;

    /**
     * The SendAction to which the ProtocolMessage was added
     */
    private final SendAction action;

    public AddMessageModification(ProtocolMessage message, SendAction action) {
        super(ModificationType.ADD_MESSAGE);
        this.message = message;
        this.action = action;
    }

    public ProtocolMessage getMessage() {
        return message;
    }

}
