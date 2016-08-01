/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package Mutator;

import Config.EvolutionaryFuzzerConfig;
import TestVector.TestVector;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;

/**
 * The Mutator is the generator of new FuzzingVectors, different Implementations
 * should implement different Strategies to generate new Workflowtraces to be
 * executed.
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public abstract class Mutator {

    protected EvolutionaryFuzzerConfig config;
    protected CertificateMutator certMutator;

    public Mutator(EvolutionaryFuzzerConfig config, CertificateMutator certMutator) {
	this.config = config;
	this.certMutator = certMutator;
    }

    /**
     * Generates a new WorkflowTrace to Fuzz the Application
     * 
     * @return
     */
    public abstract TestVector getNewMutation();
}
