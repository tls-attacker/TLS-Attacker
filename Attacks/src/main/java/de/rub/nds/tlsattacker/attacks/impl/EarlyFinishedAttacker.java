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

import de.rub.nds.tlsattacker.attacks.config.EarlyFinishedCommandConfig;
import de.rub.nds.tlsattacker.attacks.constants.EarlyFinishedVulnerabilityType;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutorFactory;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.MessageActionFactory;
import de.rub.nds.tlsattacker.core.workflow.action.SendDynamicClientKeyExchangeAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import de.rub.nds.tlsattacker.util.ConsoleLogger;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class EarlyFinishedAttacker extends Attacker<EarlyFinishedCommandConfig> {

    private final Logger LOGGER = LogManager.getLogger();

    public EarlyFinishedAttacker(EarlyFinishedCommandConfig config, Config baseConfig) {
        super(config, baseConfig);
    }

    @Override
    public void executeAttack() {
        throw new UnsupportedOperationException("Not implemented yet");
    }

    @Override
    public Boolean isVulnerable() {
        EarlyFinishedVulnerabilityType earlyFinVulnerabilityType = performCheck();
        switch (earlyFinVulnerabilityType) {
            case VULNERABLE:
                return true;
            case NOT_VULNERABLE_PROBABBlY:
            case NOT_VULNERABLE:
                return false;
            case UNKNOWN:
                return null;
        }
        return null;
    }

    public EarlyFinishedVulnerabilityType performCheck() {
        Config tlsConfig = config.createConfig();
        tlsConfig.setFiltersKeepUserSettings(false);

        WorkflowConfigurationFactory workflowConfigurationFactory = new WorkflowConfigurationFactory(tlsConfig);
        OutboundConnection connection = tlsConfig.getDefaultClientConnection();
        WorkflowTrace workflowTrace = workflowConfigurationFactory.createHelloWorkflow(connection);
        workflowTrace.addTlsAction(new SendDynamicClientKeyExchangeAction(connection.getAlias()));
        List<ProtocolMessage> messages = new LinkedList<>();
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

        if (!workflowTrace.allActionsExecuted()) {
            ConsoleLogger.CONSOLE.warn("Could not complete Workflow - Vulnerability unknown");
            return EarlyFinishedVulnerabilityType.UNKNOWN;
        }
        if (WorkflowTraceUtil.didReceiveMessage(ProtocolMessageType.ALERT, workflowTrace)) {
            ConsoleLogger.CONSOLE.info("Not vulnerable (definitely), Alert message found");
            return EarlyFinishedVulnerabilityType.NOT_VULNERABLE;
        } else if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.FINISHED, workflowTrace)) {
            ConsoleLogger.CONSOLE.error("Vulnerable (definitely), Finished message found");
            return EarlyFinishedVulnerabilityType.VULNERABLE;
        } else {
            ConsoleLogger.CONSOLE.info("Not vulnerable (probably), No Finished message found, yet also no alert");
            return EarlyFinishedVulnerabilityType.NOT_VULNERABLE_PROBABBlY;
        }
    }
}
