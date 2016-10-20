/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.controller;

import tlsattacker.fuzzer.config.EvolutionaryFuzzerConfig;
import tlsattacker.fuzzer.exceptions.IllegalCertificateMutatorException;
import tlsattacker.fuzzer.exceptions.IllegalControllerException;
import tlsattacker.fuzzer.exceptions.IllegalMutatorException;
import tlsattacker.fuzzer.mutator.Mutator;
import tlsattacker.fuzzer.mutator.NoneMutator;
import tlsattacker.fuzzer.mutator.SimpleMutator;
import tlsattacker.fuzzer.mutator.certificate.CertificateMutator;

/**
 * A factory class which generates the correct controller depending on the controller specified in the 
 * configuration object
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class ControllerFactory
{
    public static Controller getController(EvolutionaryFuzzerConfig config)
            throws IllegalControllerException, IllegalMutatorException, IllegalCertificateMutatorException {
	switch (config.getMutator()) {
            case CommandLineController.optionName:
		return new CommandLineController(config);
            default:
		throw new IllegalControllerException("Illegal Value for Controller:" + config.getController());

	}
    }
}
