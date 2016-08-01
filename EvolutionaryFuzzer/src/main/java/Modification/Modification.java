/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package Modification;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public abstract class Modification {
    private final ModificationType type;

    public Modification(ModificationType type) {
	this.type = type;
    }

    public ModificationType getType() {
	return type;
    }

}
