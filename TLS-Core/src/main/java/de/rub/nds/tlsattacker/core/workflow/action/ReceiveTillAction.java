/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.tlsattacker.core.layer.LayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.ReceiveTillLayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.constant.ImplementedLayers;
import de.rub.nds.tlsattacker.core.layer.data.DataContainer;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import jakarta.xml.bind.annotation.XmlElementRef;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@XmlRootElement
public class ReceiveTillAction extends CommonReceiveAction {

    private static final Logger LOGGER = LogManager.getLogger();

    @HoldsModifiableVariable @XmlElementRef protected ProtocolMessage<?> waitTillMessage;

    public ReceiveTillAction() {
        super();
    }

    public ReceiveTillAction(ProtocolMessage<?> waitTillMessage) {
        super();
        this.waitTillMessage = waitTillMessage;
    }

    public ReceiveTillAction(String connectionAliasAlias, ProtocolMessage<?> waitTillMessage) {
        super(connectionAliasAlias);
        this.waitTillMessage = waitTillMessage;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder("WaitTillReceive Action:\n");

        sb.append("Waiting till:");
        if ((waitTillMessage != null)) {
            sb.append(waitTillMessage.toCompactString());

        } else {
            sb.append(" (no messages set)");
        }
        sb.append("\n\tActual:");
        if ((messages != null) && (!messages.isEmpty())) {
            for (ProtocolMessage<?> message : messages) {
                sb.append(message.toCompactString());
                sb.append(", ");
            }
        } else {
            sb.append(" (no messages set)");
        }
        sb.append("\n");
        return sb.toString();
    }

    @Override
    public String toCompactString() {
        StringBuilder sb = new StringBuilder(super.toCompactString());
        if (waitTillMessage != null) {
            sb.append(" (");
            sb.append(waitTillMessage.toCompactString());
            if (sb.lastIndexOf(",") > 0) {
                sb.deleteCharAt(sb.lastIndexOf(","));
            }
            sb.append(")");
        } else {
            sb.append(" (no messages set)");
        }
        return sb.toString();
    }

    @Override
    public boolean executedAsPlanned() {
        if (messages == null) {
            return false;
        }

        for (ProtocolMessage<?> message : messages) {
            if (message.getClass().equals(waitTillMessage.getClass())) {
                return true;
            }
        }

        return false;
    }

    public ProtocolMessage<?> getWaitTillMessage() {
        return waitTillMessage;
    }

    public void setWaitTillMessage(ProtocolMessage<?> waitTillMessage) {
        this.waitTillMessage = waitTillMessage;
    }

    @Override
    public void reset() {
        messages = null;
        records = null;
        fragments = null;
        setExecuted(null);
    }

    @Override
    public int hashCode() {
        int hash = super.hashCode();
        hash = 67 * hash + Objects.hashCode(this.waitTillMessage);
        hash = 67 * hash + Objects.hashCode(this.messages);
        hash = 67 * hash + Objects.hashCode(this.records);
        hash = 67 * hash + Objects.hashCode(this.fragments);
        return hash;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final ReceiveTillAction other = (ReceiveTillAction) obj;
        return Objects.equals(this.waitTillMessage, other.waitTillMessage);
    }

    @Override
    protected List<LayerConfiguration<?>> createConfigurationList() {
        List<LayerConfiguration<?>> configurations = new ArrayList<>();
        configurations.add(
                new ReceiveTillLayerConfiguration<DataContainer<?, ?>>(
                        ImplementedLayers.MESSAGE, waitTillMessage));
        return configurations;
    }
}
