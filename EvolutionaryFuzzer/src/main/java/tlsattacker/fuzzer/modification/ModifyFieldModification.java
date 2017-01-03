/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.modification;

import de.rub.nds.tlsattacker.tls.protocol.ModifiableVariableHolder;

/**
 * A modification which indicates that a field in the WorkflowTrace was changed.
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class ModifyFieldModification extends Modification {

    /**
     * The name of the field that was modified
     */
    private final String fieldName;

    /**
     * The holder of the Field that was modifed
     */
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
