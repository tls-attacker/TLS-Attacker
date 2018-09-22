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
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import static de.rub.nds.tlsattacker.util.ConsoleLogger.CONSOLE;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author robert
 */
public class EarlyFinishedAttacker extends Attacker<EarlyFinishedCommandConfig> {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     *
     * @param config
     * @param baseConfig
     */
    public EarlyFinishedAttacker(EarlyFinishedCommandConfig config, Config baseConfig) {
        super(config, baseConfig);
    }

    @Override
    public void executeAttack() {
        throw new UnsupportedOperationException("Not implemented yet");
    }

    /**
     *
     * @return
     */
    @Override
    public Boolean isVulnerable() {
        EarlyFinishedVulnerabilityType vulnerabilityType = getVulnerabilityType();
        switch (vulnerabilityType) {
            case VULNERABLE:
                return true;
            case NOT_VULNERABLE:
            case UNKNOWN:
                return false;
        }
        return null;
    }

    /**
     *
     * @return
     */
    public EarlyFinishedVulnerabilityType getVulnerabilityType() {
        Config tlsConfig = config.createConfig();
        tlsConfig.setFiltersKeepUserSettings(false);

        WorkflowConfigurationFactory workflowConfigurationFactory = new WorkflowConfigurationFactory(tlsConfig);
        OutboundConnection connection = tlsConfig.getDefaultClientConnection();
        WorkflowTrace workflowTrace = workflowConfigurationFactory.createHelloWorkflow(connection);

        // TODO: Both the test and WorkflowConfigurationFactory are duplicates
        // of this code.
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
            CONSOLE.info("Not vulnerable (definitely), Alert message found");
            return EarlyFinishedVulnerabilityType.NOT_VULNERABLE;
        } else if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.FINISHED, workflowTrace)) {
            CONSOLE.info("Vulnerable (definitely), Finished message found");
            return EarlyFinishedVulnerabilityType.VULNERABLE;
        } else {
            CONSOLE.info("Not vulnerable (probably), No Finished message found, yet also no alert");
            return EarlyFinishedVulnerabilityType.UNKNOWN;
        }
    }

}
