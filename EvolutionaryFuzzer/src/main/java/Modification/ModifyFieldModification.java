/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package Modification;

import de.rub.nds.tlsattacker.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.tlsattacker.modifiablevariable.VariableModification;
import de.rub.nds.tlsattacker.tls.protocol.ModifiableVariableHolder;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessage;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class ModifyFieldModification extends Modification {
    private final String fieldName;
    private final ModifiableVariableHolder modificationHolder;

    public ModifyFieldModification(String fieldName, ModifiableVariableHolder modificationHolder) {
	super(ModificationType.MODIFY_FIELD);
	this.fieldName = fieldName;
	this.modificationHolder = modificationHolder;
    }

    public String getFieldName() {
	return fieldName;
    }

    public ModifiableVariableHolder getModificationHolder() {
	return modificationHolder;
    }

}
