/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.alert;

import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.tlsattacker.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.tls.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.tls.constants.AlertDescription;
import de.rub.nds.tlsattacker.tls.constants.AlertLevel;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import java.util.Objects;

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
	this.level = ModifiableVariableFactory.safelySetValue(this.level, level);
    }

    public void setLevel(ModifiableByte level) {
	this.level = level;
    }

    public ModifiableByte getDescription() {
	return description;
    }

    public void setDescription(byte description) {
	this.description = ModifiableVariableFactory.safelySetValue(this.description, description);
    }

    public void setDescription(ModifiableByte description) {
	this.description = description;
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
	sb.append("\nALERT message:\n  Level: ");
	if (level != null) {
	    sb.append(AlertLevel.getAlertLevel(level.getValue()));
	} else {
	    sb.append("null");
	}
	sb.append("\n  Description: ");
	if (description != null) {
	    sb.append(AlertDescription.getAlertDescription(description.getValue()));
	} else {
	    sb.append("null");
	}
	return sb.toString();
    }

    @Override
    public String toCompactString() {
	StringBuilder sb = new StringBuilder();

	sb.append("ALERT (");
	if (level != null && level.getValue() != null) {
	    sb.append(AlertLevel.getAlertLevel(level.getValue()).toString());
	} else {
	    sb.append("null");
	}
	sb.append(", ");
	if (description != null && description.getValue() != null) {
	    sb.append(AlertDescription.getAlertDescription(description.getValue()).toString());
	} else {
	    sb.append("null");
	}
	sb.append(")");
	return sb.toString();
    }

    @Override
    public ProtocolMessageHandler getProtocolMessageHandler(TlsContext tlsContext) {
	AlertHandler ah = new AlertHandler(tlsContext);
	ah.setProtocolMessage(this);
	return ah;
    }

    @Override
    public boolean equals(Object obj) {
	if (!(obj instanceof AlertMessage)) {
	    return false;
	}
	if (obj == this) {
	    return true;
	}
	AlertMessage alert = (AlertMessage) obj;
	return (Objects.equals(alert.getLevel().getValue(), this.getLevel().getValue()))
		&& (Objects.equals(alert.getDescription().getValue(), alert.getDescription().getValue()));

    }

    @Override
    public int hashCode() {
	int hash = 7;
	hash = 73 * hash + Objects.hashCode(this.level.getValue());
	hash = 73 * hash + Objects.hashCode(this.description.getValue());
	return hash;
    }
}
