/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.impl;

import de.rub.nds.tlsattacker.attacks.config.PaddingOracleCommandConfig;
import de.rub.nds.tlsattacker.attacks.exception.PaddingOracleUnstableException;
import de.rub.nds.tlsattacker.attacks.padding.PaddingVectorGenerator;
import de.rub.nds.tlsattacker.attacks.padding.PaddingVectorGeneratorFactory;
import de.rub.nds.tlsattacker.attacks.util.response.EqualityError;
import de.rub.nds.tlsattacker.attacks.util.response.EqualityErrorTranslator;
import de.rub.nds.tlsattacker.attacks.util.response.FingerPrintChecker;
import de.rub.nds.tlsattacker.attacks.util.response.ResponseExtractor;
import de.rub.nds.tlsattacker.attacks.util.response.ResponseFingerprint;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.record.AbstractRecord;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.util.LogLevel;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutorFactory;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import java.io.IOException;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;

/**
 * Executes a padding oracle attack check. It logs an error in case the tested
 * server is vulnerable to poodle.
 */
public class PaddingOracleAttacker extends Attacker<PaddingOracleCommandConfig> {

    private final Config tlsConfig;

    public PaddingOracleAttacker(PaddingOracleCommandConfig paddingOracleConfig) {
        super(paddingOracleConfig);
        tlsConfig = paddingOracleConfig.createConfig();
    }

    @Override
    public void executeAttack() {
        throw new UnsupportedOperationException("Not implemented yet");
    }

    public State executeTlsFlow(WorkflowTrace trace) {
        tlsConfig.setAddSignatureAndHashAlgrorithmsExtension(true);
        tlsConfig.setEarlyStop(true);
        tlsConfig.setStopActionsAfterFatal(true);
        tlsConfig.setQuickReceive(true);
        tlsConfig.setWorkflowExecutorShouldClose(false);
        State state = new State(tlsConfig, trace);
        WorkflowExecutor workflowExecutor = WorkflowExecutorFactory.createWorkflowExecutor(
                tlsConfig.getWorkflowExecutorType(), state);
        workflowExecutor.executeWorkflow();
        return state;
    }

    @Override
    public Boolean isVulnerable() {
        LOGGER.log(LogLevel.CONSOLE_OUTPUT,
                "A server is considered vulnerable to this attack if it responds differently to the test vectors.");
        LOGGER.log(LogLevel.CONSOLE_OUTPUT, "A server is considered secure if it always responds the same way.");
        HashMap<Integer, List<ResponseFingerprint>> responseMap = createResponseMap();

        EqualityError error = getEqualityError(responseMap);
        if (error == EqualityError.SOCKET_EXCEPTION || error == EqualityError.SOCKET_STATE) {
            LOGGER.log(LogLevel.CONSOLE_OUTPUT, "Found a candidate for a Socket difference performing rescan");
            HashMap<Integer, List<ResponseFingerprint>> responseMapTwo = createResponseMap();
            EqualityError errorTwo = getEqualityError(responseMapTwo);
            if (error == errorTwo && lookEqual(responseMap, responseMapTwo)) {
                HashMap<Integer, List<ResponseFingerprint>> responseMapThree = createResponseMap();
                EqualityError errorThree = getEqualityError(responseMapThree);
                if (error == errorThree && lookEqual(responseMap, responseMapThree)) {
                    LOGGER.log(LogLevel.CONSOLE_OUTPUT,
                            "Found an equality Error in a SocketState, performed to rescans and it still presisted");
                    LOGGER.log(LogLevel.CONSOLE_OUTPUT, "The Server is very likely vulnerabble");
                } else {
                    LOGGER.log(LogLevel.CONSOLE_OUTPUT, "Rescan revealed a false positive");
                    return false;
                }
            } else {
                LOGGER.log(LogLevel.CONSOLE_OUTPUT, "Rescan revealed a false positive");
                return false;
            }
        }
        LOGGER.log(LogLevel.CONSOLE_OUTPUT, EqualityErrorTranslator.translation(error, null, null));
        if (error != EqualityError.NONE) {

            for (List<ResponseFingerprint> fingerprintList : responseMap.values()) {
                System.out.println("----------------Map-----------------");
                for (ResponseFingerprint fingerprint : fingerprintList) {
                    System.out.println(fingerprint.toString());
                }
            }
        }
        return error != EqualityError.NONE;
    }

    public boolean lookEqual(HashMap<Integer, List<ResponseFingerprint>> responseMapOne,
            HashMap<Integer, List<ResponseFingerprint>> responseMapTwo) {
        for (Integer key : responseMapOne.keySet()) {
            List<ResponseFingerprint> listOne = responseMapOne.get(key);
            List<ResponseFingerprint> listTwo = responseMapTwo.get(key);
            if (listOne.size() != listTwo.size()) {
                throw new PaddingOracleUnstableException(
                        "The padding Oracle seems to be unstable - there is something going terrible wrong. We recommend manual analysis");
            }
            for (int i = 0; i < listOne.size(); i++) {
                if (FingerPrintChecker.checkEquality(listOne.get(i), listTwo.get(i), false) != EqualityError.NONE) {
                    return false;
                }
            }
        }
        return true;
    }

    public HashMap<Integer, List<ResponseFingerprint>> createResponseMap() {
        int macSize = AlgorithmResolver.getMacAlgorithm(tlsConfig.getDefaultSelectedProtocolVersion(),
                tlsConfig.getDefaultSelectedCipherSuite()).getSize();
        int blockSize = AlgorithmResolver.getCipher(tlsConfig.getDefaultSelectedCipherSuite())
                .getNonceBytesFromHandshake();
        PaddingVectorGenerator generator = PaddingVectorGeneratorFactory.getPaddingVectorGenerator(config);
        List<WorkflowTrace> traceList = generator.getPaddingOracleVectors(tlsConfig);

        HashMap<Integer, List<ResponseFingerprint>> responseMap = new HashMap<>();
        for (WorkflowTrace trace : traceList) {
            State state;
            try {
                state = executeTlsFlow(trace);
            } catch (WorkflowExecutionException | ConfigurationException E) {
                LOGGER.warn(E);
                LOGGER.warn("TLS-Attacker failed execute a Handshake. Skipping to next record");
                continue;
            }
            if (state.getWorkflowTrace().allActionsExecuted()) {
                ResponseFingerprint fingerprint = ResponseExtractor.getFingerprint(state);
                clearConnections(state);
                AbstractRecord lastRecord = state.getWorkflowTrace().getLastSendingAction().getSendRecords()
                        .get(state.getWorkflowTrace().getLastSendingAction().getSendRecords().size() - 1);
                int length = ((Record) lastRecord).getLength().getValue();
                List<ResponseFingerprint> responseFingerprintList = responseMap.get(length);
                if (responseFingerprintList == null) {
                    responseFingerprintList = new LinkedList<>();
                    responseMap.put(length, responseFingerprintList);
                }
                responseFingerprintList.add(fingerprint);
            } else {
                LOGGER.warn("Could not execute Workflow. Something went wrong... Check the debug output for more information");
            }
        }
        return responseMap;
    }

    public EqualityError getEqualityError(HashMap<Integer, List<ResponseFingerprint>> responseMap) {
        for (List<ResponseFingerprint> list : responseMap.values()) {
            ResponseFingerprint fingerprint = list.get(0);
            for (int i = 1; i < list.size(); i++) {
                EqualityError error = FingerPrintChecker.checkEquality(fingerprint, list.get(i), true);
                if (error != EqualityError.NONE) {
                    LOGGER.log(LogLevel.CONSOLE_OUTPUT, "Found an equality Error: " + error);
                    LOGGER.debug("Fingerprint1: " + fingerprint.toString());
                    LOGGER.debug("Fingerprint2: " + list.get(i).toString());

                    return error;
                }
            }
        }
        return EqualityError.NONE;
    }

    private void clearConnections(State state) {
        try {
            state.getTlsContext().getTransportHandler().closeConnection();
        } catch (IOException ex) {
            LOGGER.debug(ex);
        }
    }
}
