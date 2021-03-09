/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.attacks.impl;

import static de.rub.nds.tlsattacker.util.ConsoleLogger.CONSOLE;

import de.rub.nds.tlsattacker.attacks.config.PaddingOracleCommandConfig;
import de.rub.nds.tlsattacker.attacks.exception.AttackFailedException;
import de.rub.nds.tlsattacker.attacks.exception.OracleUnstableException;
import de.rub.nds.tlsattacker.attacks.padding.PaddingTraceGenerator;
import de.rub.nds.tlsattacker.attacks.padding.PaddingTraceGeneratorFactory;
import de.rub.nds.tlsattacker.attacks.padding.PaddingVectorGenerator;
import de.rub.nds.tlsattacker.attacks.padding.VectorResponse;
import de.rub.nds.tlsattacker.attacks.padding.vector.FingerprintTaskVectorPair;
import de.rub.nds.tlsattacker.attacks.padding.vector.PaddingVector;
import de.rub.nds.tlsattacker.attacks.task.FingerPrintTask;
import de.rub.nds.tlsattacker.attacks.util.response.EqualityError;
import de.rub.nds.tlsattacker.attacks.util.response.EqualityErrorTranslator;
import de.rub.nds.tlsattacker.attacks.util.response.FingerPrintChecker;
import de.rub.nds.tlsattacker.attacks.util.response.ResponseFingerprint;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.task.TlsTask;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Executes a padding oracle attack check. It logs an error in case the tested server is vulnerable to poodle.
 */
public class PaddingOracleAttacker extends Attacker<PaddingOracleCommandConfig> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final Config tlsConfig;

    private boolean increasingTimeout = true;

    private long additionalTimeout = 1000;

    private long additionalTcpTimeout = 5000;

    private List<VectorResponse> fullResponseMap;

    private EqualityError resultError;

    private CipherSuite testedSuite;

    private ProtocolVersion testedVersion;

    private final ParallelExecutor executor;

    private boolean shakyScans = false;
    private boolean erroneousScans = false;

    /**
     *
     * @param paddingOracleConfig
     * @param baseConfig
     */
    public PaddingOracleAttacker(PaddingOracleCommandConfig paddingOracleConfig, Config baseConfig) {
        super(paddingOracleConfig, baseConfig);
        tlsConfig = getTlsConfig();
        executor = new ParallelExecutor(1, 3);
    }

    /**
     *
     * @param paddingOracleConfig
     * @param baseConfig
     * @param executor
     */
    public PaddingOracleAttacker(PaddingOracleCommandConfig paddingOracleConfig, Config baseConfig,
        ParallelExecutor executor) {
        super(paddingOracleConfig, baseConfig);
        tlsConfig = getTlsConfig();
        this.executor = executor;
    }

    @Override
    public void executeAttack() {
        throw new UnsupportedOperationException("Not implemented yet");
    }

    /**
     *
     * @return
     */
    @Override
    public Boolean isVulnerable() {
        CONSOLE
            .info("A server is considered vulnerable to this attack if it responds differently to the test vectors.");
        CONSOLE.info("A server is considered secure if it always responds the same way.");
        EqualityError referenceError = null;
        fullResponseMap = new LinkedList<>();
        try {
            for (int i = 0; i < config.getNumberOfIterations(); i++) {
                List<VectorResponse> responseMap = createVectorResponseList();
                this.fullResponseMap.addAll(responseMap);
            }
        } catch (AttackFailedException e) {
            CONSOLE.info(e.getMessage());
            return null;
        }
        referenceError = getEqualityError(fullResponseMap);
        if (referenceError != EqualityError.NONE) {
            CONSOLE.info("Found a behavior difference within the responses. The server could be vulnerable.");
        } else {
            CONSOLE
                .info("Found no behavior difference within the responses. The server is very likely not vulnerable.");
        }

        CONSOLE.info(EqualityErrorTranslator.translation(referenceError, null, null));
        if (referenceError != EqualityError.NONE || LOGGER.getLevel().isMoreSpecificThan(Level.INFO)) {
            LOGGER.debug("-------------(Not Grouped)-----------------");
            for (VectorResponse vectorResponse : fullResponseMap) {
                LOGGER.debug(vectorResponse.toString());
            }
        }

        resultError = referenceError;
        return referenceError != EqualityError.NONE;
    }

    /**
     *
     * @param  responseVectorListOne
     * @param  responseVectorListTwo
     * @return
     */
    public boolean lookEqual(List<VectorResponse> responseVectorListOne, List<VectorResponse> responseVectorListTwo) {
        boolean result = true;
        if (responseVectorListOne.size() != responseVectorListTwo.size()) {
            throw new OracleUnstableException(
                "The padding oracle seems to be unstable - there is something going terrible wrong. We recommend manual analysis");
        }

        for (VectorResponse vectorResponseOne : responseVectorListOne) {
            // Find equivalent
            VectorResponse equivalentVector = null;
            for (VectorResponse vectorResponseTwo : responseVectorListTwo) {
                if (vectorResponseOne.getVector().equals(vectorResponseTwo.getVector())) {
                    equivalentVector = vectorResponseTwo;
                    break;
                }
            }
            if (vectorResponseOne.getFingerprint() == null) {
                LOGGER.error("First vector has no fingerprint:" + testedSuite + " - " + testedVersion);
                result = false;
                continue;
            }
            if (equivalentVector == null) {
                LOGGER.error("Equivalent vector is null:" + testedSuite + " - " + testedVersion);
                result = false;
                continue;
            }
            if (equivalentVector.getFingerprint() == null) {
                LOGGER.warn("Equivalent vector has no fingerprint:" + testedSuite + " - " + testedVersion);
                result = false;
                continue;
            }

            EqualityError error =
                FingerPrintChecker.checkEquality(vectorResponseOne.getFingerprint(), equivalentVector.getFingerprint());
            if (error != EqualityError.NONE) {
                LOGGER.warn("There is an error between rescan:" + error + " - " + testedSuite + " - " + testedVersion);
                result = false;
            }
        }
        return result;
    }

    /**
     *
     * @return
     */
    public List<VectorResponse> createVectorResponseList() {
        PaddingTraceGenerator generator = PaddingTraceGeneratorFactory.getPaddingTraceGenerator(config);
        PaddingVectorGenerator vectorGenerator = generator.getVectorGenerator();
        List<TlsTask> taskList = new LinkedList<>();
        List<FingerprintTaskVectorPair> stateVectorPairList = new LinkedList<>();
        for (PaddingVector vector : vectorGenerator.getVectors(tlsConfig.getDefaultSelectedCipherSuite(),
            tlsConfig.getDefaultHighestClientProtocolVersion())) {
            State state = new State(tlsConfig, generator.getPaddingOracleWorkflowTrace(tlsConfig, vector));
            FingerPrintTask fingerPrintTask = new FingerPrintTask(state, additionalTimeout, increasingTimeout,
                executor.getReexecutions(), additionalTcpTimeout);
            taskList.add(fingerPrintTask);
            stateVectorPairList.add(new FingerprintTaskVectorPair(fingerPrintTask, vector));
        }
        List<VectorResponse> tempResponseVectorList = new LinkedList<>();
        executor.bulkExecuteTasks(taskList);
        for (FingerprintTaskVectorPair pair : stateVectorPairList) {
            ResponseFingerprint fingerprint = null;
            if (pair.getFingerPrintTask().isHasError()) {
                erroneousScans = true;
                LOGGER.warn("Could not extract fingerprint for " + pair.toString());
            } else {
                testedSuite = pair.getFingerPrintTask().getState().getTlsContext().getSelectedCipherSuite();
                testedVersion = pair.getFingerPrintTask().getState().getTlsContext().getSelectedProtocolVersion();
                if (testedSuite == null || testedVersion == null) {
                    LOGGER.fatal("Could not find ServerHello after successful extraction");
                    throw new OracleUnstableException("Fatal Extraction error");
                }
                fingerprint = pair.getFingerPrintTask().getFingerprint();
                tempResponseVectorList.add(new VectorResponse(pair.getVector(), fingerprint));
            }
        }
        return tempResponseVectorList;
    }

    /**
     * This assumes that the responseVectorList only contains comparable vectors
     *
     * @param  responseVectorList
     * @return
     */
    public EqualityError getEqualityError(List<VectorResponse> responseVectorList) {

        for (VectorResponse responseOne : responseVectorList) {
            for (VectorResponse responseTwo : responseVectorList) {
                if (responseOne == responseTwo) {
                    continue;
                }
                EqualityError error =
                    FingerPrintChecker.checkEquality(responseOne.getFingerprint(), responseTwo.getFingerprint());
                if (error != EqualityError.NONE) {
                    CONSOLE.info("Found an EqualityError: " + error);
                    LOGGER.debug("Fingerprint1: " + responseOne.getFingerprint().toString());
                    LOGGER.debug("Fingerprint2: " + responseTwo.getFingerprint().toString());
                    return error;
                }

            }
        }
        return EqualityError.NONE;
    }

    public EqualityError getResultError() {
        return resultError;
    }

    public List<VectorResponse> getResponseMapList() {
        return fullResponseMap;
    }

    /**
     *
     * @return
     */
    public CipherSuite getTestedSuite() {
        return testedSuite;
    }

    /**
     *
     * @return
     */
    public ProtocolVersion getTestedVersion() {
        return testedVersion;
    }

    /**
     *
     * @return
     */
    public boolean isShakyScans() {
        return shakyScans;
    }

    public boolean isErroneousScans() {
        return erroneousScans;
    }

    public boolean isIncreasingTimeout() {
        return increasingTimeout;
    }

    public void setIncreasingTimeout(boolean increasingTimeout) {
        this.increasingTimeout = increasingTimeout;
    }

    public long getAdditionalTimeout() {
        return additionalTimeout;
    }

    public void setAdditionalTimeout(long additionalTimeout) {
        this.additionalTimeout = additionalTimeout;
    }

    public long getAdditionalTcpTimeout() {
        return additionalTcpTimeout;
    }

    public void setAdditionalTcpTimeout(long additionalTcpTimeout) {
        this.additionalTcpTimeout = additionalTcpTimeout;
    }

}
