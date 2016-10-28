/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.mutator;

import java.util.logging.Logger;
import tlsattacker.fuzzer.config.EvolutionaryFuzzerConfig;
import tlsattacker.fuzzer.exceptions.IllegalMutatorException;
import tlsattacker.fuzzer.mutator.certificate.CertificateMutator;

/**
 * A factory class which chooses the correct mutator as specified in the
 * configuration file.
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class MutatorFactory {

    /**
     * Generates the correct mutator as specified in the config
     * @param certMutator CertificateMutator to use
     * @param config Config to use
     * @return A newly generated Mutator
     * @throws IllegalMutatorException If the specified Mutator is invalid
     */
    public static Mutator getMutator(CertificateMutator certMutator, EvolutionaryFuzzerConfig config)
	    throws IllegalMutatorException {
	switch (config.getMutator()) {
	    case SimpleMutator.optionName:
		return new SimpleMutator(config, certMutator);
	    case NoneMutator.optionName:
		return new NoneMutator(config, certMutator);
	    default:
		throw new IllegalMutatorException("Illegal Value for Mutator:" + config.getMutator());

	}
    }

    private MutatorFactory() {
    }

    private static final Logger LOG = Logger.getLogger(MutatorFactory.class.getName());
}
