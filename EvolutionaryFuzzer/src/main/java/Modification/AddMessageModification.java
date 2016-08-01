/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package Modification;

import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessage;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class AddMessageModification extends Modification {
    private final ProtocolMessage message;

    public AddMessageModification(ProtocolMessage message) {
	super(ModificationType.ADD_MESSAGE);
	this.message = message;
    }

    public ProtocolMessage getMessage() {
	return message;
    }

}
