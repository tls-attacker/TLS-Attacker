/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.modification;

import java.util.logging.Logger;

/**
 * A modification which indicates that a new ToggleEncryptionAction was added to
 * the WorkflowTrace
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class AddToggleEncrytionActionModification extends Modification {

    /**
     * The position in the WorkflowTrace where the Action was added
     */
    private int actionPosition;

    public AddToggleEncrytionActionModification(int ActionPosition) {
        super(ModificationType.TOGGLE_ENCRYPTION);
        this.actionPosition = actionPosition;
    }

    public int getActionPosition() {
        return actionPosition;
    }

    private static final Logger LOG = Logger.getLogger(AddToggleEncrytionActionModification.class.getName());

}
