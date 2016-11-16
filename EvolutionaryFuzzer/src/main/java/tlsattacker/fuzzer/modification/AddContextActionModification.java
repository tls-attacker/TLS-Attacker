/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.modification;

import de.rub.nds.tlsattacker.tls.workflow.action.TLSAction;
import java.util.logging.Logger;

/**
 * A modification which indicates that a new action was added to the
 * WorkflowTrace which changes a field in the TlsContext
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class AddContextActionModification extends Modification {

    /**
     * The action that was added
     */
    private final TLSAction action;

    public AddContextActionModification(ModificationType type, TLSAction action) {
        super(type);
        this.action = action;
    }

    public TLSAction getAction() {
        return action;
    }

    private static final Logger LOG = Logger.getLogger(AddContextActionModification.class.getName());

}
