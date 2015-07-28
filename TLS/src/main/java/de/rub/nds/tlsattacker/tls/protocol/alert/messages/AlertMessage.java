/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS.
 *
 * Copyright (C) 2015 Chair for Network and Data Security,
 *                    Ruhr University Bochum
 *                    (juraj.somorovsky@rub.de)
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

import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.tlsattacker.modifiablevariable.singlebyte.ModifiableByte;
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
     * config array used to configure alert message
     */
    private byte[] config;
    /**
     * alert level
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    ModifiableByte level;

    /**
     * alert description
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    ModifiableByte description;

    public AlertMessage() {
	this.protocolMessageType = ProtocolMessageType.ALERT;
    }

    public AlertMessage(ConnectionEnd messageIssuer) {
	this();
	this.messageIssuer = messageIssuer;
    }

    public ModifiableByte getLevel() {
	return level;
    }

    public void setLevel(byte level) {
	if (this.level == null) {
	    this.level = new ModifiableByte();
	}
	this.level.setOriginalValue(level);
    }

    public ModifiableByte getDescription() {
	return description;
    }

    public void setDescription(byte description) {
	if (this.description == null) {
	    this.description = new ModifiableByte();
	}
	this.description.setOriginalValue(description);
    }

    public byte[] getConfig() {
	return config;
    }

    public void setConfig(byte[] config) {
	this.config = config;
    }

    public void setConfig(AlertLevel level, AlertDescription description) {
	config = new byte[2];
	config[0] = level.getValue();
	config[1] = description.getValue();
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
	AlertHandler ah = new AlertHandler(tlsContext);
	ah.setProtocolMessage(this);
	return ah;
    }
}
