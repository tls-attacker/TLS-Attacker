/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.modification;

import de.rub.nds.tlsattacker.tls.protocol.extension.ExtensionMessage;
import java.util.logging.Logger;

/**
 * A modification which indicates that a new Extension was added to a Hello message
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class AddExtensionModification extends Modification {

    /**
     *
     */
    private ExtensionMessage message;

    /**
     *
     * @param message
     */
    public AddExtensionModification(ExtensionMessage message) {
	super(ModificationType.ADD_EXTENSION);
	this.message = message;
    }

    /**
     *
     * @return
     */
    public ExtensionMessage getMessage() {
	return message;
    }
    private static final Logger LOG = Logger.getLogger(AddExtensionModification.class.getName());

}
