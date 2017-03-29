/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.impl;

import de.rub.nds.tlsattacker.attacks.config.BleichenbacherCommandConfig;
import de.rub.nds.tlsattacker.attacks.pkcs1.PKCS1VectorGenerator;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ByteArrayModificationFactory;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.tls.Attacker;
import de.rub.nds.tlsattacker.tls.constants.AlertDescription;
import de.rub.nds.tlsattacker.tls.constants.AlertLevel;
import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.tls.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.RSAClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.util.CertificateFetcher;
import de.rub.nds.tlsattacker.tls.util.LogLevel;
import de.rub.nds.tlsattacker.tls.util.WorkflowTraceSerializer;
import de.rub.nds.tlsattacker.tls.workflow.TlsConfig;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowExecutorFactory;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.interfaces.RSAPublicKey;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import javax.xml.bind.JAXBException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Sends differently formatted PKCS#1 messages to the TLS server and observes
 * the server responses. In case there are differences in the server responses,
 * it is very likely that it is possible to execute Bleichenbacher attacks.
 *
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class BleichenbacherAttacker extends Attacker<BleichenbacherCommandConfig> {

    private static final Logger LOGGER = LogManager.getLogger(BleichenbacherAttacker.class);

    public BleichenbacherAttacker(BleichenbacherCommandConfig config) {
        super(config, false);
    }

    @Override
    public void executeAttack() {

    }

    private ProtocolMessage executeTlsFlow(byte[] encryptedPMS) {
        // we are initializing a new connection in every loop step, since most
        // of the known servers close the connection after an invalid handshake
        TlsConfig tlsConfig = config.createConfig();
        TlsContext tlsContext = new TlsContext(tlsConfig);
        WorkflowExecutor workflowExecutor = WorkflowExecutorFactory.createWorkflowExecutor(tlsConfig.getExecutorType(),
                tlsContext);
        WorkflowTrace trace = tlsContext.getWorkflowTrace();
        RSAClientKeyExchangeMessage cke = (RSAClientKeyExchangeMessage) trace
                .getFirstConfiguredSendMessageOfType(HandshakeMessageType.CLIENT_KEY_EXCHANGE);
        ModifiableByteArray epms = new ModifiableByteArray();
        epms.setModification(ByteArrayModificationFactory.explicitValue(encryptedPMS));
        cke.setSerializedPublicKey(epms);
        workflowExecutor.executeWorkflow();
        return trace.getAllActuallyReceivedMessages().get(trace.getAllActuallyReceivedMessages().size() - 1);
    }

    @Override
    public Boolean isVulnerable() {
        RSAPublicKey publicKey;
        TlsConfig tlsConfig = config.createConfig();
        publicKey = (RSAPublicKey) CertificateFetcher.fetchServerPublicKey(tlsConfig);
        LOGGER.info("Fetched the following server public key: " + publicKey);

        List<ProtocolMessage> protocolMessages = new LinkedList<>();
        byte[][] vectors = PKCS1VectorGenerator.generatePkcs1Vectors(publicKey, config.getType());
        for (byte[] vector : vectors) {
            ProtocolMessage pm = executeTlsFlow(vector);
            protocolMessages.add(pm);
        }

        LOGGER.info("The following list of protocol messages was found (the last protocol message in the client-server communication):");
        for (ProtocolMessage pm : protocolMessages) {
            LOGGER.info("Sent Type: {}", pm.getProtocolMessageType());
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
            LOGGER.log(LogLevel.CONSOLE_OUTPUT, "{}, NOT vulnerable, one message found: {}", tlsConfig.getHost(),
                    sb.toString());
            return false;
        } else {
            LOGGER.log(LogLevel.CONSOLE_OUTPUT, "{}, Vulnerable (probably), found: {}", tlsConfig.getHost(),
                    sb.toString());
            return true;
        }
    }
}
