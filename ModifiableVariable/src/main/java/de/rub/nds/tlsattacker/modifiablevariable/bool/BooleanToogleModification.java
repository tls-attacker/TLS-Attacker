/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.modifiablevariable.bool;

import de.rub.nds.tlsattacker.modifiablevariable.VariableModification;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
@XmlRootElement
@XmlType(propOrder = { "xor", "modificationFilter", "postModification" })
public class BooleanToogleModification extends VariableModification<Boolean> {

    public BooleanToogleModification() {
    }

    @Override
    protected Boolean modifyImplementationHook(Boolean input) {
        if (input == null) {
            input = Boolean.FALSE;
        }
        return !input;
    }
}
