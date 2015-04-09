/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS.
 *
 * Copyright (C) 2015 Juraj Somorovsky
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.rub.nds.tlsattacker.tls.protocol.alert.messages;

import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariable;
import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.tls.protocol.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.tls.protocol.alert.constants.AlertDescription;
import de.rub.nds.tlsattacker.tls.protocol.alert.constants.AlertLevel;
import de.rub.nds.tlsattacker.tls.protocol.alert.handlers.AlertHandler;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class AlertMessage extends ProtocolMessage {
    /**
     * alert level
     */
    ModifiableVariable<Byte> level;

    /**
     * alert description
     */
    ModifiableVariable<Byte> description;
    /**
     * resulting message
     */
    private ModifiableVariable<byte[]> completeResultingMessage;

    public AlertMessage() {
	this.protocolMessageType = ProtocolMessageType.ALERT;
    }

    public AlertMessage(ConnectionEnd messageIssuer) {
	this();
	this.messageIssuer = messageIssuer;
    }

    public ModifiableVariable<Byte> getLevel() {
	return level;
    }

    public void setLevel(byte level) {
	if (this.level == null) {
	    this.level = new ModifiableVariable<>();
	}
	this.level.setOriginalValue(level);
    }

    public ModifiableVariable<Byte> getDescription() {
	return description;
    }

    public void setDescription(byte description) {
	if (this.description == null) {
	    this.description = new ModifiableVariable<>();
	}
	this.description.setOriginalValue(description);
    }

    @Override
    public String toString() {
	StringBuilder sb = new StringBuilder();
	sb.append("\nALERT message:\n  Level: ").append(AlertLevel.getAlertLevel(level.getValue()))
		.append("\n  Description: ").append(AlertDescription.getAlertDescription(description.getValue()));
	return sb.toString();
    }

    @Override
    public ProtocolMessageHandler getProtocolMessageHandler(TlsContext tlsContext) {
	return new AlertHandler(tlsContext);
    }

    public ModifiableVariable getCompleteResultingMessage() {
	return completeResultingMessage;
    }

    public void setCompleteResultingMessage(ModifiableVariable<byte[]> completeResultingMessage) {
	this.completeResultingMessage = completeResultingMessage;
    }

    public void setCompleteResultingMessage(byte[] completeResultingMessage) {
	this.completeResultingMessage = ModifiableVariableFactory.safelySetValue(this.completeResultingMessage,
		completeResultingMessage);
    }
}
