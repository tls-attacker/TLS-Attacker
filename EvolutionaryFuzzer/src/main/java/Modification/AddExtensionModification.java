/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package Modification;

import de.rub.nds.tlsattacker.tls.protocol.extension.ExtensionMessage;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class AddExtensionModification extends Modification {
    private ExtensionMessage message;

    public AddExtensionModification(ExtensionMessage message) {
	super(ModificationType.ADD_EXTENSION);
	this.message = message;
    }

    public ExtensionMessage getMessage() {
	return message;
    }

}
