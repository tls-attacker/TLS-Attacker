/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.impl;

import java.util.LinkedList;
import java.util.List;

import de.rub.nds.tlsattacker.attacks.actions.EarlyCcsAction;
import de.rub.nds.tlsattacker.attacks.config.EarlyCCSCommandConfig;
import de.rub.nds.tlsattacker.attacks.config.EarlyFinishedCommandConfig;
import de.rub.nds.tlsattacker.attacks.constants.EarlyCcsVulnerabilityType;
import de.rub.nds.tlsattacker.attacks.impl.EarlyCCSAttacker.TargetVersion;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.util.LogLevel;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutorFactory;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ActivateEncryptionAction;
import de.rub.nds.tlsattacker.core.workflow.action.ChangeMasterSecretAction;
import de.rub.nds.tlsattacker.core.workflow.action.MessageActionFactory;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;

public class EarlyFinishedAttacker extends Attacker<EarlyFinishedCommandConfig> {

    public EarlyFinishedAttacker(EarlyFinishedCommandConfig config) {
        super(config);
    }

    @Override
    public void executeAttack() {
        throw new UnsupportedOperationException("Not implemented yet");
    }

    @Override
    public Boolean isVulnerable() {
        EarlyCcsVulnerabilityType earlyCcsVulnerabilityType = getEarlyCcsVulnerabilityType();
        switch (earlyCcsVulnerabilityType) {
            case VULN_EXPLOITABLE:
            case VULN_NOT_EXPLOITABLE:
                return true;
            case NOT_VULNERABLE:
                return false;
            case UNKNOWN:
                return null;
        }
        return null;
    }

    public boolean checkTargetVersion() {
        Config tlsConfig = config.createConfig();
        tlsConfig.setFiltersKeepUserSettings(false);

        WorkflowConfigurationFactory workflowConfigurationFactory = new WorkflowConfigurationFactory(tlsConfig);
        OutboundConnection connection = tlsConfig.getDefaultClientConnection();
        WorkflowTrace workflowTrace = workflowConfigurationFactory.createHelloWorkflow(connection);

        // TODO: This shares code with WorkflowConfigurationFactory, and not in
        // a good way :-)
        List<ProtocolMessage> messages = new LinkedList<>();
        workflowConfigurationFactory.addClientKeyExchangeMessage(messages);
        messages.add(new ChangeCipherSpecMessage(tlsConfig));
        workflowTrace.addTlsAction(MessageActionFactory.createAction(connection, ConnectionEndType.CLIENT, messages));

        messages = new LinkedList<>();
        messages.add(new ChangeCipherSpecMessage(tlsConfig));
        messages.add(new FinishedMessage(tlsConfig));
        workflowTrace.addTlsAction(MessageActionFactory.createAction(connection, ConnectionEndType.SERVER, messages));

        State state = new State(tlsConfig, workflowTrace);
        WorkflowExecutor workflowExecutor = WorkflowExecutorFactory.createWorkflowExecutor(
                tlsConfig.getWorkflowExecutorType(), state);
        workflowExecutor.executeWorkflow();

        if (WorkflowTraceUtil.didReceiveMessage(ProtocolMessageType.ALERT, workflowTrace)) {
            LOGGER.log(LogLevel.CONSOLE_OUTPUT, "Not vulnerable (definitely), Alert message found");
            return false;
        } else if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.FINISHED, workflowTrace)) {
            LOGGER.log(LogLevel.CONSOLE_OUTPUT, "Vulnerable (definitely), Finished message found");
            return true;
        } else {
            LOGGER.log(LogLevel.CONSOLE_OUTPUT,
                    "Not vulnerable (probably), No Finished message found, yet also no alert");
            return false;
        }
    }

    public EarlyCcsVulnerabilityType getEarlyCcsVulnerabilityType() {
        // TODO: Changed return value
        if (checkTargetVersion()) {
            return EarlyCcsVulnerabilityType.VULN_EXPLOITABLE;
        }
        return EarlyCcsVulnerabilityType.NOT_VULNERABLE;
    }

}
