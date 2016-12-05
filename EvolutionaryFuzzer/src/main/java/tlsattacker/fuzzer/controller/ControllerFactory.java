/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.controller;

import java.util.logging.Logger;
import tlsattacker.fuzzer.config.EvolutionaryFuzzerConfig;
import tlsattacker.fuzzer.exceptions.FuzzerConfigurationException;
import tlsattacker.fuzzer.exceptions.IllegalAnalyzerException;
import tlsattacker.fuzzer.exceptions.IllegalCertificateMutatorException;
import tlsattacker.fuzzer.exceptions.IllegalControllerException;
import tlsattacker.fuzzer.exceptions.IllegalMutatorException;

/**
 * A factory class which generates the correct controller depending on the
 * controller specified in the configuration object
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class ControllerFactory {

    /**
     * Chooses the correct Controller depending on the controller specified in
     * the config
     * 
     * @param config
     *            Config object to use
     * @return Correct Controller instance
     * @throws IllegalControllerException
     *             If an invalid controller is selected
     * @throws IllegalMutatorException
     *             If an invalid Mutator is selected
     * @throws IllegalCertificateMutatorException
     *             If an invalid CertificateMutator is selected
     */
    public static Controller getController(EvolutionaryFuzzerConfig config) throws IllegalControllerException,
            IllegalMutatorException, IllegalCertificateMutatorException, IllegalAnalyzerException, FuzzerConfigurationException {
        switch (config.getController()) {
            case CommandLineController.optionName:
                CommandLineController controller = new CommandLineController(config);
                controller.start();
                return controller;
            default:
                throw new IllegalControllerException("Illegal Value for Controller:" + config.getController());

        }
    }

    /**
     *
     */
    private ControllerFactory() {
    }

    private static final Logger LOG = Logger.getLogger(ControllerFactory.class.getName());
}
