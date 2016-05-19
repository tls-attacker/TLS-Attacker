/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.config;

import com.beust.jcommander.Parameter;
import de.rub.nds.tlsattacker.tls.config.ClientCommandConfig;
import de.rub.nds.tlsattacker.tls.constants.HeartbeatMode;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTraceType;

/**
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class HeartbleedCommandConfig extends ClientCommandConfig {

    public static final String ATTACK_COMMAND = "heartbleed";

    @Parameter(names = "-payload_length", description = "Payload length sent in the client heartbeat message")
    Integer payloadLength;

    public HeartbleedCommandConfig() {
	workflowTraceType = WorkflowTraceType.FULL;
	payloadLength = 20000;
	heartbeatMode = HeartbeatMode.PEER_ALLOWED_TO_SEND;
    }

    public Integer getPayloadLength() {
	return payloadLength;
    }

    public void setPayloadLength(Integer payloadLength) {
	this.payloadLength = payloadLength;
    }
}
