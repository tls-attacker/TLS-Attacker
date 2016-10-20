/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.modification;

import de.rub.nds.tlsattacker.tls.protocol.ModifiableVariableHolder;
import java.util.logging.Logger;

/**
 * A modification which indicates that a field in the WorkflowTrace was changed.
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class ModifyFieldModification extends Modification {

    /**
     *
     */
    private final String fieldName;

    /**
     *
     */
    private final ModifiableVariableHolder modificationHolder;

    /**
     *
     * @param fieldName
     * @param modificationHolder
     */
    public ModifyFieldModification(String fieldName, ModifiableVariableHolder modificationHolder) {
	super(ModificationType.MODIFY_FIELD);
	this.fieldName = fieldName;
	this.modificationHolder = modificationHolder;
    }

    /**
     *
     * @return
     */
    public String getFieldName() {
	return fieldName;
    }

    /**
     *
     * @return
     */
    public ModifiableVariableHolder getModificationHolder() {
	return modificationHolder;
    }
    private static final Logger LOG = Logger.getLogger(ModifyFieldModification.class.getName());

}
