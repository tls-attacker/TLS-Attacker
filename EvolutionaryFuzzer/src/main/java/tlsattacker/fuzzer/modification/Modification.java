/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.modification;

import java.io.Serializable;

/**
 * A modification represents something that was changed in a TestVector
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public abstract class Modification implements Serializable {

    /**
     * The type of the modification
     */
    private final ModificationType type;

    public Modification(ModificationType type) {
        this.type = type;
    }

    public ModificationType getType() {
        return type;
    }
}
