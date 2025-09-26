/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import jakarta.xml.bind.annotation.XmlRootElement;

@XmlRootElement(name = "TightReceiveTill")
public class TightReceiveTillAction extends ReceiveTillAction {

    public TightReceiveTillAction() {
        super();
    }

    public TightReceiveTillAction(String connectionAlias) {
        super(connectionAlias);
    }

    public TightReceiveTillAction(ProtocolMessage waitTillMessage) {
        super(waitTillMessage);
    }

    public TightReceiveTillAction(String connectionAliasAlias, ProtocolMessage waitTillMessage) {
        super(connectionAliasAlias, waitTillMessage);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder("TightWaitTillReceive Action:\n");

        sb.append("Waiting till:");
        if ((getWaitTillMessage() != null)) {
            sb.append(getWaitTillMessage().toCompactString());

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
        if (getWaitTillMessage() != null) {
            sb.append(" (");
            sb.append(getWaitTillMessage().toCompactString());
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
    protected boolean shouldProcessTrailingContainers() {
        return false;
    }
}
