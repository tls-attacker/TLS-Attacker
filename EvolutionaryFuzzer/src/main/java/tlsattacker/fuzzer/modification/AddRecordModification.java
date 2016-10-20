/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.modification;

import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessage;

/**
 * A modification which indicates that a new record was added to the WorkflowTrace
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class AddRecordModification extends Modification {

    /**
     *
     */
    private final ProtocolMessage message;

    /**
     *
     * @param message
     */
    public AddRecordModification(ProtocolMessage message) {
	super(ModificationType.ADD_RECORD);
	this.message = message;
    }

    /**
     *
     * @return
     */
    public ProtocolMessage getMessage() {
	return message;
    }

}
