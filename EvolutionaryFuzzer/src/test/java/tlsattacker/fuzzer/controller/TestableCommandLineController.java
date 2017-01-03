/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.controller;

import tlsattacker.fuzzer.config.EvolutionaryFuzzerConfig;
import tlsattacker.fuzzer.exceptions.FuzzerConfigurationException;
import tlsattacker.fuzzer.exceptions.IllegalAnalyzerException;
import tlsattacker.fuzzer.exceptions.IllegalCertificateMutatorException;
import tlsattacker.fuzzer.exceptions.IllegalMutatorException;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class TestableCommandLineController extends CommandLineController {

    public TestableCommandLineController(EvolutionaryFuzzerConfig config) throws IllegalMutatorException,
            IllegalCertificateMutatorException, IllegalAnalyzerException, FuzzerConfigurationException {
        super(config);

    }

}
