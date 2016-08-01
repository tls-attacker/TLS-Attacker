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
public class RemoveMessageModification extends Modification {
    private final ProtocolMessage message;
    private final int position;

    public RemoveMessageModification(ProtocolMessage message, int position) {
	super(ModificationType.ADD_MESSAGE);
	this.message = message;
	this.position = position;
    }

    public int getPosition() {
	return position;
    }

    public ProtocolMessage getMessage() {
	return message;
    }

}
