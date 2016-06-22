/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package tls.rub.evolutionaryfuzzer;

import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;

/**
 * The Mutator is the generator of new FuzzingVectors, different Implementations
 * should implement different Strategies to generate new Workflowtraces to be
 * executed.
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public abstract class Mutator
{

    /**
     * Generates a new WorkflowTrace to Fuzz the Application
     * @return
     */
    public abstract WorkflowTrace getNewMutation();
}
