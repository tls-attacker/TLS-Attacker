/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.controller;

import java.util.logging.Logger;
import tlsattacker.fuzzer.config.EvolutionaryFuzzerConfig;
import tlsattacker.fuzzer.exceptions.IllegalAgentException;
import tlsattacker.fuzzer.exceptions.IllegalAnalyzerException;
import tlsattacker.fuzzer.exceptions.IllegalCertificateMutatorException;
import tlsattacker.fuzzer.exceptions.IllegalControllerException;
import tlsattacker.fuzzer.exceptions.IllegalExecutorException;
import tlsattacker.fuzzer.exceptions.IllegalMutatorException;
import tlsattacker.fuzzer.executor.Executor;
import tlsattacker.fuzzer.executor.MultiTLSExecutor;
import tlsattacker.fuzzer.executor.SingleTLSExecutor;
import tlsattacker.fuzzer.testvector.TestVector;

/**
 * A factory class which generates the correct Executor depending on the
 * Executor specified in the configuration object
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class ExecutorFactory {

    /**
     * Chooses the correct Executor depending on the Executor specified in
     * the config
     * 
     * @param config
     *            Config object to use
     * @param testVector
     * @return Correct Executor instance
     *             If an invalid controller is selected
     * @throws tlsattacker.fuzzer.exceptions.IllegalAgentException Thrown if the Executor cannot generate the Specified Agent
     * @throws tlsattacker.fuzzer.exceptions.IllegalExecutorException Thrown if the Executor cannot be generated
     */
    public static Executor getExecutor(EvolutionaryFuzzerConfig config, TestVector testVector) throws IllegalAgentException, IllegalExecutorException {
        switch (config.getExecutor()) {
            case SingleTLSExecutor.optionName:
                SingleTLSExecutor executor = new SingleTLSExecutor(config, testVector);
                return executor;
            case MultiTLSExecutor.optionName:
                return new MultiTLSExecutor(config, testVector);
            default:
                throw new IllegalExecutorException("Illegal Value for Executor:" + config.getExecutor());

        }
    }

    /**
     *
     */
    private ExecutorFactory() {
    }

    private static final Logger LOG = Logger.getLogger(ControllerFactory.class.getName());
}
