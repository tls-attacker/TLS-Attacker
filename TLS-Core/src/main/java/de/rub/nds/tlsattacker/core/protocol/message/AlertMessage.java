/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.modifiablevariable.util.UnformattedByteArrayAdapter;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.AlertLevel;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.handler.AlertHandler;
import de.rub.nds.tlsattacker.core.protocol.parser.AlertParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.AlertPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.AlertSerializer;
import de.rub.nds.tlsattacker.core.state.Context;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.adapters.XmlJavaTypeAdapter;
import java.io.InputStream;
import java.util.Objects;

@XmlRootElement(name = "Alert")
public class AlertMessage extends ProtocolMessage {

    /** config array used to configure alert message */
    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    private byte[] config;

    /** alert level */
    @ModifiableVariableProperty private ModifiableByte level;

    /** alert description */
    @ModifiableVariableProperty private ModifiableByte description;

    public AlertMessage() {
        super();
        this.protocolMessageType = ProtocolMessageType.ALERT;
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
        sb.append("AlertMessage:");
        sb.append("\n  Level: ");
        if (level != null) {
            if (AlertLevel.getAlertLevel(level.getValue()) == AlertLevel.UNDEFINED) {
                sb.append(level.getValue());
            } else {
                sb.append(AlertLevel.getAlertLevel(level.getValue()));
            }
        } else {
            sb.append("null");
        }
        sb.append("\n  Description: ");
        if (description != null) {
            if (AlertDescription.getAlertDescription(description.getValue()) == null) {
                sb.append(description.getValue());
            } else {
                sb.append(AlertDescription.getAlertDescription(description.getValue()));
            }
        } else {
            sb.append("null");
        }
        return sb.toString();
    }

    @Override
    public String toCompactString() {
        StringBuilder sb = new StringBuilder();
        String levelString;
        String descriptionString;

        // Determine level string
        if (level != null && level.getValue() != null) {
            levelString = AlertLevel.getAlertLevel(level.getValue()).name();
        } else if (config != null && config.length == 2) {
            // Use config as fallback for level
            AlertLevel alertLevel = AlertLevel.getAlertLevel((byte) config[0]);
            if (alertLevel != null) {
                levelString = alertLevel.name();
            } else {
                levelString = "" + config[0];
            }
        } else {
            levelString = "not configured";
        }

        // Determine description string
        if (description != null && description.getValue() != null) {
            AlertDescription desc = AlertDescription.getAlertDescription(description.getValue());
            if (desc != null) {
                descriptionString = desc.name();
            } else {
                descriptionString = "" + description.getValue();
            }
        } else if (config != null && config.length == 2) {
            // Use config as fallback for description
            AlertDescription desc = AlertDescription.getAlertDescription((byte) config[1]);
            if (desc != null) {
                descriptionString = desc.name();
            } else {
                descriptionString = "" + config[1];
            }
        } else {
            descriptionString = "not configured";
        }

        sb.append("Alert(").append(levelString).append(",").append(descriptionString).append(")");
        return sb.toString();
    }

    @Override
    public String toShortString() {
        AlertDescription alertDescription =
                AlertDescription.getAlertDescription(description.getValue());
        if (alertDescription == null) {
            return "UKNOWN ALERT";
        }
        return alertDescription.toString();
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
        if (alert.getLevel() != null
                && alert.getDescription() != null
                && this.getLevel() != null
                && this.getDescription() != null) {

            return Objects.equals(alert.getLevel().getValue(), this.getLevel().getValue())
                    && Objects.equals(
                            alert.getDescription().getValue(), this.getDescription().getValue());
        } else {
            // If level is null we do not compare the values
            if (this.getLevel() == null || alert.getLevel() == null) {
                return (Objects.equals(
                        alert.getDescription().getValue(), this.getDescription().getValue()));
            } else {
                return (Objects.equals(alert.getLevel().getValue(), this.getLevel().getValue()));
            }
        }
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 73 * hash + Objects.hashCode(this.level.getValue());
        hash = 73 * hash + Objects.hashCode(this.description.getValue());
        return hash;
    }

    @Override
    public AlertHandler getHandler(Context context) {
        return new AlertHandler(context.getTlsContext());
    }

    @Override
    public AlertParser getParser(Context context, InputStream stream) {
        return new AlertParser(stream);
    }

    @Override
    public AlertPreparator getPreparator(Context context) {
        return new AlertPreparator(context.getChooser(), this);
    }

    @Override
    public AlertSerializer getSerializer(Context context) {
        return new AlertSerializer(this);
    }
}
