/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.impl;

import de.rub.nds.modifiablevariable.VariableModification;
import de.rub.nds.modifiablevariable.bytearray.ByteArrayModificationFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.attacks.config.Cve20162107CommandConfig;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.AlertLevel;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.KeyExchangeAlgorithm;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.core.record.AbstractRecord;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutorFactory;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Tests for the availability of the OpenSSL padding oracle (CVE-2016-2107).
 */
/**
 * Deprecated 18.4.2019 - There is no need for this class. it is completly
 * integrated into the padding oracle attacker
 */
@Deprecated
public class Cve20162107Attacker extends Attacker<Cve20162107CommandConfig> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final List<ProtocolMessage> lastMessages;

    private boolean vulnerable;

    /**
     *
     * @param config
     * @param baseConfig
     */
    public Cve20162107Attacker(Cve20162107CommandConfig config, Config baseConfig) {
        super(config, baseConfig);
        lastMessages = new LinkedList<>();
    }

    @Override
    public void executeAttack() {
        throw new UnsupportedOperationException("Not implemented yet");
    }

    private Boolean executeAttackRound(ProtocolVersion version, CipherSuite suite) {
        Config tlsConfig = getTlsConfig();
        tlsConfig.setDefaultSelectedCipherSuite(suite);
        tlsConfig.setDefaultClientSupportedCiphersuites(suite);
        KeyExchangeAlgorithm keyExchangeAlgorithm = AlgorithmResolver.getKeyExchangeAlgorithm(suite);
        if (keyExchangeAlgorithm != null && keyExchangeAlgorithm.name().toUpperCase().contains("EC")) {
            tlsConfig.setAddECPointFormatExtension(true);
            tlsConfig.setAddEllipticCurveExtension(true);
        } else {
            tlsConfig.setAddECPointFormatExtension(false);
            tlsConfig.setAddEllipticCurveExtension(false);
        }
        tlsConfig.setHighestProtocolVersion(version);
        LOGGER.info("Testing {}, {}", version.name(), suite.name());

        WorkflowConfigurationFactory cf = new WorkflowConfigurationFactory(tlsConfig);
        WorkflowTrace trace = cf.createWorkflowTrace(WorkflowTraceType.HANDSHAKE, RunningModeType.CLIENT);
        SendAction sendAction = (SendAction) trace.getLastSendingAction();

        // We need 2-3 Records,one for every message, while the last one will
        // have the modified padding
        List<AbstractRecord> records = new LinkedList<>();
        Record record = createRecordWithBadPadding();
        tlsConfig.setCreateIndividualRecords(true);
        records.add(new Record(tlsConfig));
        if (sendAction.getSendMessages().size() > 2) {
            records.add(new Record(tlsConfig));
        }
        records.add(record);
        sendAction.setRecords(records);

        // Remove last two server messages (CCS and Finished). Instead of them,
        // an alert will be sent.
        AlertMessage alertMessage = new AlertMessage(tlsConfig);

        ReceiveAction action = (ReceiveAction) (trace.getLastMessageAction());
        List<ProtocolMessage> messages = new LinkedList<>();
        messages.add(alertMessage);
        action.setExpectedMessages(messages);
        State state = new State(tlsConfig, trace);
        WorkflowExecutor workflowExecutor = WorkflowExecutorFactory.createWorkflowExecutor(
                tlsConfig.getWorkflowExecutorType(), state);

        try {
            workflowExecutor.executeWorkflow();
        } catch (WorkflowExecutionException ex) {
            LOGGER.warn("Not possible to finalize the defined workflow");
            LOGGER.debug(ex.getLocalizedMessage());
        }
        // The Server has to answer to our ClientHello with a ServerHello
        // Message, else he does not support the offered Ciphersuite and
        // protocol version
        if (!WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO, trace)) {
            LOGGER.info("Did not receive ServerHello. Skipping...");
            return false;
        }
        ProtocolMessage lm = WorkflowTraceUtil.getLastReceivedMessage(trace);
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
                && AlertDescription.getAlertDescription(((AlertMessage) lm).getDescription().getValue()) == AlertDescription.RECORD_OVERFLOW) {
            LOGGER.info("  Vulnerable");
            return true;
        } else {
            LOGGER.info(suite.name() + " - " + version.name() + ": Not Vulnerable");
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
        r.prepareComputations();
        ModifiableByteArray plainData = new ModifiableByteArray();
        VariableModification<byte[]> modifier = ByteArrayModificationFactory.explicitValue(plain);
        plainData.setModification(modifier);
        r.getComputations().setPlainRecordBytes(plainData);
        return r;
    }

    /**
     *
     * @return
     */
    @Override
    public Boolean isVulnerable() {
        List<ProtocolVersion> versions = config.getVersions();
        Config tlsConfig = getTlsConfig();
        List<CipherSuite> ciphers = new LinkedList<>();
        if (tlsConfig.getDefaultClientSupportedCiphersuites().isEmpty()) {
            for (CipherSuite cs : CipherSuite.getImplemented()) {
                if (cs.isCBC()) {
                    ciphers.add(cs);
                }
            }
        } else {
            ciphers = tlsConfig.getDefaultClientSupportedCiphersuites();
        }

        for (ProtocolVersion version : versions) {
            for (CipherSuite suite : ciphers) {
                try {
                    vulnerable |= executeAttackRound(version, suite);
                } catch (Throwable t) {
                    LOGGER.warn("Problem while testing " + version.name() + " with Ciphersuite " + suite.name());
                    LOGGER.debug(t);
                }
            }
        }

        if (vulnerable) {
            LOGGER.info("VULNERABLE");
        } else {
            LOGGER.info("NOT VULNERABLE");
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
