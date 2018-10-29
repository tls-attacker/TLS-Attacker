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
import de.rub.nds.tlsattacker.attacks.constants.PaddingRecordGeneratorType;
import de.rub.nds.tlsattacker.attacks.exception.AttackFailedException;
import de.rub.nds.tlsattacker.attacks.exception.PaddingOracleUnstableException;
import de.rub.nds.tlsattacker.attacks.padding.PaddingTraceGenerator;
import de.rub.nds.tlsattacker.attacks.padding.PaddingTraceGeneratorFactory;
import de.rub.nds.tlsattacker.attacks.padding.PaddingVectorGenerator;
import de.rub.nds.tlsattacker.attacks.padding.VectorResponse;
import de.rub.nds.tlsattacker.attacks.padding.vector.PaddingVector;
import de.rub.nds.tlsattacker.attacks.padding.vector.FingerprintTaskVectorPair;
import de.rub.nds.tlsattacker.attacks.task.FingerPrintTask;
import de.rub.nds.tlsattacker.attacks.util.response.EqualityError;
import de.rub.nds.tlsattacker.attacks.util.response.EqualityErrorTranslator;
import de.rub.nds.tlsattacker.attacks.util.response.FingerPrintChecker;
import de.rub.nds.tlsattacker.attacks.util.response.ResponseExtractor;
import de.rub.nds.tlsattacker.attacks.util.response.ResponseFingerprint;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.task.TlsTask;
import static de.rub.nds.tlsattacker.util.ConsoleLogger.CONSOLE;
import java.io.IOException;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Executes a padding oracle attack check. It logs an error in case the tested
 * server is vulnerable to poodle.
 */
public class PaddingOracleAttacker extends Attacker<PaddingOracleCommandConfig> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final Config tlsConfig;

    private boolean groupRecords = true;

    private List<VectorResponse> vectorResponseList;
    private List<VectorResponse> vectorResponseListTwo;
    private List<VectorResponse> vectorResponseListThree;

    private CipherSuite testedSuite;

    private ProtocolVersion testedVersion;

    private final ParallelExecutor executor;

    private boolean shakyScans = false;
    private boolean errornousScans = false;

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
        if (config.getRecordGeneratorType() == PaddingRecordGeneratorType.VERY_SHORT) {
            groupRecords = false;
        }
        CONSOLE.info("A server is considered vulnerable to this attack if it responds differently to the test vectors.");
        CONSOLE.info("A server is considered secure if it always responds the same way.");
        EqualityError error;

        try {
            vectorResponseList = createVectorResponseList();
            error = getEqualityError(vectorResponseList);
            if (error != EqualityError.NONE) {
                CONSOLE.info("Found a side channel. Rescanning to confirm.");
                vectorResponseListTwo = createVectorResponseList();
                EqualityError errorTwo = getEqualityError(vectorResponseListTwo);
                if (error == errorTwo && lookEqual(vectorResponseList, vectorResponseListTwo)) {
                    vectorResponseListThree = createVectorResponseList();
                    EqualityError errorThree = getEqualityError(vectorResponseListThree);
                    if (error == errorThree && lookEqual(vectorResponseList, vectorResponseListThree)) {
                        CONSOLE.info("Found an equality Error.");
                        CONSOLE.info("The Server is very likely vulnerabble");
                    } else {
                        CONSOLE.info("Rescan revealed a false positive");
                        shakyScans = true;
                        return false;
                    }
                } else {
                    CONSOLE.info("Rescan revealed a false positive");
                    shakyScans = true;
                    return false;
                }
            }
        } catch (AttackFailedException E) {
            CONSOLE.info(E.getMessage());
            return null;
        }
        CONSOLE.info(EqualityErrorTranslator.translation(error, null, null));
        if (error != EqualityError.NONE || LOGGER.getLevel().isMoreSpecificThan(Level.INFO)) {
            LOGGER.debug("-------------(Not Grouped)-----------------");
            for (VectorResponse vectorResponse : vectorResponseList) {
                LOGGER.debug(vectorResponse.toString());
            }
        }

        return error != EqualityError.NONE;
    }

    /**
     *
     * @param responseVectorListOne
     * @param responseVectorListTwo
     * @return
     */
    public boolean lookEqual(List<VectorResponse> responseVectorListOne, List<VectorResponse> responseVectorListTwo) {
        boolean result = true;
        if (responseVectorListOne.size() != responseVectorListTwo.size()) {
            throw new PaddingOracleUnstableException(
                    "The padding Oracle seems to be unstable - there is something going terrible wrong. We recommend manual analysis");
        }

        for (VectorResponse vectorResponseOne : responseVectorListOne) {
            // Find equivalent
            VectorResponse equivalentVector = null;
            for (VectorResponse vectorResponseTwo : responseVectorListTwo) {
                if (vectorResponseOne.getPaddingVector().equals(vectorResponseTwo.getPaddingVector())) {
                    equivalentVector = vectorResponseTwo;
                    break;
                }
            }
            if (vectorResponseOne.getFingerprint() == null) {
                vectorResponseOne.setShaky(true);
                vectorResponseOne.setErrorDuringHandshake(true);
                result = false;
                continue;
            }
            if (equivalentVector == null) {
                vectorResponseOne.setShaky(true);
                result = false;
                vectorResponseOne.setMissingEquivalent(true);
                continue;
            }
            if (equivalentVector.getFingerprint() == null) {
                equivalentVector.setShaky(true);
                equivalentVector.setErrorDuringHandshake(true);
                result = false;
                continue;
            }

            EqualityError error = FingerPrintChecker.checkEquality(vectorResponseOne.getFingerprint(),
                    equivalentVector.getFingerprint(), true);
            if (error != EqualityError.NONE) {
                result = false;
                vectorResponseOne.setShaky(true);
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
            FingerPrintTask fingerPrintTask = new FingerPrintTask(state, 3);
            taskList.add(fingerPrintTask);
            stateVectorPairList.add(new FingerprintTaskVectorPair(fingerPrintTask, vector));
        }
        List<VectorResponse> tempResponseVectorList = new LinkedList<>();
        executor.bulkExecuteTasks(taskList);
        for (FingerprintTaskVectorPair pair : stateVectorPairList) {
            ResponseFingerprint fingerprint = null;
            if (pair.getFingerPrintTask().getState().getWorkflowTrace().allActionsExecuted()) {
                testedSuite = pair.getFingerPrintTask().getState().getTlsContext().getSelectedCipherSuite();
                testedVersion = pair.getFingerPrintTask().getState().getTlsContext().getSelectedProtocolVersion();
                if (testedSuite == null || testedVersion == null) {
                    // Did not receive ServerHello?!
                    errornousScans = true;
                }
                fingerprint = pair.getFingerPrintTask().getFingerprint();
                tempResponseVectorList.add(new VectorResponse(pair.getVector(), fingerprint, testedVersion,
                        testedSuite, tlsConfig.getDefaultApplicationMessageData().getBytes().length));
            } else {

                LOGGER.warn("Could not execute Workflow. Something went wrong... Check the debug output for more information");
                VectorResponse vectorResponse = new VectorResponse(pair.getVector(), null, testedVersion, testedSuite,
                        tlsConfig.getDefaultApplicationMessageData().getBytes().length);
                vectorResponse.setErrorDuringHandshake(true);
                tempResponseVectorList.add(vectorResponse);
                errornousScans = true;
            }
        }
        return tempResponseVectorList;
    }

    /**
     *
     * @param responseVectorList
     * @return
     */
    public EqualityError getEqualityError(List<VectorResponse> responseVectorList) {
        // TODO this comparision does too many equivalnce tests but is a easier
        // to read?
        for (VectorResponse responseOne : responseVectorList) {
            for (VectorResponse responseTwo : responseVectorList) {
                boolean shouldCompare = true;
                if (responseOne.getLength() == null || responseTwo.getLength() == null) {
                    shouldCompare = false;
                }
                if (shouldCompare || !groupRecords) {
                    EqualityError error = FingerPrintChecker.checkEquality(responseOne.getFingerprint(),
                            responseTwo.getFingerprint(), true);
                    if (error != EqualityError.NONE) {
                        CONSOLE.info("Found an equality Error: " + error);
                        LOGGER.debug("Fingerprint1: " + responseOne.getFingerprint().toString());
                        LOGGER.debug("Fingerprint2: " + responseTwo.getFingerprint().toString());
                        return error;
                    }
                }
            }
        }
        return EqualityError.NONE;
    }

    /**
     *
     * @return
     */
    public List<VectorResponse> getVectorResponseList() {
        return vectorResponseList;
    }

    /**
     * The responseVector list of the first rescan
     *
     * @return
     */
    public List<VectorResponse> getVectorResponseListTwo() {
        return vectorResponseListTwo;
    }

    /**
     * The responseVector list of the second rescan
     *
     * @return
     */
    public List<VectorResponse> getVectorResponseListThree() {
        return vectorResponseListThree;
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

    public boolean isErrornousScans() {
        return errornousScans;
    }
}
