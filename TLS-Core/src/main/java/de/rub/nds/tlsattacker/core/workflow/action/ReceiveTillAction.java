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
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.container.ActionHelperUtil;
import jakarta.xml.bind.annotation.XmlElementRef;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@XmlRootElement(name = "ReceiveTill")
public class ReceiveTillAction extends CommonReceiveAction {

    private static final Logger LOGGER = LogManager.getLogger();

    @HoldsModifiableVariable @XmlElementRef protected ProtocolMessage waitTillMessage;

    public ReceiveTillAction() {
        super();
    }

    public ReceiveTillAction(String connectionAlias) {
        super(connectionAlias);
    }

    public ReceiveTillAction(ProtocolMessage waitTillMessage) {
        super();
        this.waitTillMessage = waitTillMessage;
    }

    public ReceiveTillAction(String connectionAliasAlias, ProtocolMessage waitTillMessage) {
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
        if ((getReceivedMessages() != null) && (!getReceivedMessages().isEmpty())) {
            for (ProtocolMessage message : getReceivedMessages()) {
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
        if (getReceivedMessages() == null) {
            return false;
        }

        for (ProtocolMessage message : getReceivedMessages()) {
            if (message.getClass().equals(waitTillMessage.getClass())) {
                return true;
            }
        }

        return false;
    }

    public ProtocolMessage getWaitTillMessage() {
        return waitTillMessage;
    }

    public void setWaitTillMessage(ProtocolMessage waitTillMessage) {
        this.waitTillMessage = waitTillMessage;
    }

    @Override
    protected List<LayerConfiguration<?>> createLayerConfiguration(State state) {
        TlsContext tlsContext = state.getTlsContext(getConnectionAlias());
        List<LayerConfiguration<?>> configurationList = new LinkedList<>();
        configurationList.add(
                new ReceiveTillLayerConfiguration<ProtocolMessage>(
                        ImplementedLayers.MESSAGE, waitTillMessage));
        return ActionHelperUtil.sortAndAddOptions(
                tlsContext.getLayerStack(), false, getActionOptions(), configurationList);
    }
}
