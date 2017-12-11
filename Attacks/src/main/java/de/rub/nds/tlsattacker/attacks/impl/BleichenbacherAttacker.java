/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.impl;

import de.rub.nds.tlsattacker.attacks.config.BleichenbacherCommandConfig;
import de.rub.nds.tlsattacker.attacks.pkcs1.BleichenbacherWorkflowGenerator;
import de.rub.nds.tlsattacker.attacks.pkcs1.BleichenbacherWorkflowType;
import de.rub.nds.tlsattacker.attacks.pkcs1.Pkcs1Vector;
import de.rub.nds.tlsattacker.attacks.pkcs1.Pkcs1VectorGenerator;
import de.rub.nds.tlsattacker.attacks.util.response.EqualityError;
import de.rub.nds.tlsattacker.attacks.util.response.EqualityErrorTranslator;
import de.rub.nds.tlsattacker.attacks.util.response.FingerPrintChecker;
import de.rub.nds.tlsattacker.attacks.util.response.ResponseExtractor;
import de.rub.nds.tlsattacker.attacks.util.response.ResponseFingerprint;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.util.CertificateFetcher;
import de.rub.nds.tlsattacker.core.util.LogLevel;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutorFactory;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import java.io.IOException;
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
        RSAPublicKey publicKey;
        publicKey = (RSAPublicKey) CertificateFetcher.fetchServerPublicKey(tlsConfig);
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
                return true;
            }
        }

        return false;
    }

    private EqualityError isVulnerable(BleichenbacherWorkflowType bbWorkflowType, List<Pkcs1Vector> pkcs1Vectors) {
        List<ResponseFingerprint> responseFingerprintList = new LinkedList<>();
        for (Pkcs1Vector pkcs1Vector : pkcs1Vectors) {
            State state = executeTlsFlow(bbWorkflowType, pkcs1Vector.getEncryptedValue());
            ResponseFingerprint fingerprint = ResponseExtractor.getFingerprint(state);
            clearConnections(state);
            responseFingerprintList.add(fingerprint);
        }
        if (responseFingerprintList.isEmpty()) {
            LOGGER.warn("Could not extract Fingerprints");
            return null;
        }
        for (int i = 0; i < responseFingerprintList.size(); i++) {
            ResponseFingerprint fingerprint = responseFingerprintList.get(i);
            Pkcs1Vector pkcs1Vector = pkcs1Vectors.get(i);
            LOGGER.debug("\n PKCS#1 vector: {}\n Fingerprint: {}", pkcs1Vector.getDescription(),
                    fingerprint.toString());
        }
        ResponseFingerprint fingerprint = responseFingerprintList.get(0);
        for (int i = 1; i < responseFingerprintList.size(); i++) {
            EqualityError error = FingerPrintChecker.checkEquality(fingerprint, responseFingerprintList.get(i), false);
            if (error != EqualityError.NONE) {
                LOGGER.log(LogLevel.CONSOLE_OUTPUT, "Found a difference in responses in the {}.",
                        bbWorkflowType.getDescription());
                LOGGER.log(LogLevel.CONSOLE_OUTPUT,
                        EqualityErrorTranslator.translation(error, fingerprint, responseFingerprintList.get(i)));
                LOGGER.debug("Fingerprint1: {}", fingerprint.toString());
                LOGGER.debug("Fingerprint2: {}", responseFingerprintList.get(i).toString());
                return error;
            }
        }
        return EqualityError.NONE;
    }

    @Override
    public void executeAttack() {
        // removed for now
        throw new UnsupportedOperationException("Not implemented yet");
    }

    private void clearConnections(State state) {
        try {
            state.getTlsContext().getTransportHandler().closeConnection();
        } catch (IOException ex) {
            LOGGER.debug(ex);
        }
    }
}
