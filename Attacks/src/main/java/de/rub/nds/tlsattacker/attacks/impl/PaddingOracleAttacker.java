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
import de.rub.nds.tlsattacker.attacks.padding.vector.StatePaddingOracleVectorPair;
import de.rub.nds.tlsattacker.attacks.util.response.EqualityError;
import de.rub.nds.tlsattacker.attacks.util.response.EqualityErrorTranslator;
import de.rub.nds.tlsattacker.attacks.util.response.FingerPrintChecker;
import de.rub.nds.tlsattacker.attacks.util.response.ResponseExtractor;
import de.rub.nds.tlsattacker.attacks.util.response.ResponseFingerprint;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.record.AbstractRecord;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import static de.rub.nds.tlsattacker.util.ConsoleLogger.CONSOLE;
import java.io.IOException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
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

    private CipherSuite testedSuite;

    private ProtocolVersion testedVersion;

    private final ParallelExecutor executor;

    private boolean shakyScans = false;

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
                List<VectorResponse> responseMapTwo = createVectorResponseList();
                EqualityError errorTwo = getEqualityError(responseMapTwo);
                if (error == errorTwo && lookEqual(vectorResponseList, responseMapTwo)) {
                    List<VectorResponse> responseMapThree = createVectorResponseList();
                    EqualityError errorThree = getEqualityError(responseMapThree);
                    if (error == errorThree && lookEqual(vectorResponseList, responseMapThree)) {
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
            if (equivalentVector == null) {
                throw new PaddingOracleUnstableException("Could not find equivalent Vector - something went wrong. "
                        + vectorResponseOne.getPaddingVector().toString());
            }

            if (FingerPrintChecker.checkEquality(vectorResponseOne.getFingerprint(), equivalentVector.getFingerprint(),
                    false) != EqualityError.NONE) {
                return false;
            }
        }
        return true;
    }

    /**
     *
     * @return
     */
    public List<VectorResponse> createVectorResponseList() {

        PaddingTraceGenerator generator = PaddingTraceGeneratorFactory.getPaddingTraceGenerator(config);
        PaddingVectorGenerator vectorGenerator = generator.getVectorGenerator();
        List<State> stateList = new LinkedList<>();
        List<StatePaddingOracleVectorPair> stateVectorPairList = new LinkedList<>();
        for (PaddingVector vector : vectorGenerator.getVectors(tlsConfig.getDefaultSelectedCipherSuite(),
                tlsConfig.getDefaultHighestClientProtocolVersion())) {
            State state = new State(tlsConfig, generator.getPaddingOracleWorkflowTrace(tlsConfig, vector));
            stateList.add(state);
            stateVectorPairList.add(new StatePaddingOracleVectorPair(state, vector));
        }
        List<VectorResponse> tempResponseVectorList = new LinkedList<>();
        executor.bulkExecute(stateList);
        for (StatePaddingOracleVectorPair pair : stateVectorPairList) {
            ResponseFingerprint fingerprint = null;
            if (pair.getState().getWorkflowTrace().allActionsExecuted()) {
                testedSuite = pair.getState().getTlsContext().getSelectedCipherSuite();
                testedVersion = pair.getState().getTlsContext().getSelectedProtocolVersion();
                if (testedSuite == null || testedVersion == null) {
                    // Did not receive ClientHello?!
                }
                fingerprint = ResponseExtractor.getFingerprint(pair.getState());
                clearConnections(pair.getState());
                tempResponseVectorList.add(new VectorResponse(pair.getVector(), fingerprint, testedVersion,
                        testedSuite, tlsConfig.getDefaultApplicationMessageData().getBytes().length));
            } else {
                shakyScans = true;
                LOGGER.warn("Could not execute Workflow. Something went wrong... Check the debug output for more information");
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
                if (groupRecords && shouldCompare) {
                    shouldCompare &= (responseOne.getLength() == responseTwo.getLength());
                }
                if (shouldCompare) {
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

    private void clearConnections(State state) {
        try {
            state.getTlsContext().getTransportHandler().closeConnection();
        } catch (IOException ex) {
            LOGGER.debug(ex);
        }
    }

    /**
     *
     * @return
     */
    public List<VectorResponse> getResponseMap() {
        return vectorResponseList;
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
}
