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
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.http.HttpMessage;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.record.Record;
import jakarta.xml.bind.annotation.XmlElementRef;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@XmlRootElement
public class ReceiveTillAction extends CommonReceiveAction implements ReceivingAction {

    private static final Logger LOGGER = LogManager.getLogger();

    @HoldsModifiableVariable @XmlElementRef protected ProtocolMessage waitTillMessage;

    public ReceiveTillAction() {
        super();
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
        if ((messages != null) && (!messages.isEmpty())) {
            for (ProtocolMessage message : messages) {
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

        for (ProtocolMessage message : messages) {
            if (message.getClass().equals(waitTillMessage.getClass())) {
                return true;
            }
        }

        return false;
    }

    public ProtocolMessage getWaitTillMessage() {
        return waitTillMessage;
    }

    void setReceivedMessages(List<ProtocolMessage> receivedMessages) {
        this.messages = receivedMessages;
    }

    void setReceivedRecords(List<Record> receivedRecords) {
        this.records = receivedRecords;
    }

    void setReceivedFragments(List<DtlsHandshakeMessageFragment> fragments) {
        this.fragments = fragments;
    }

    public void setWaitTillMessage(ProtocolMessage waitTillMessage) {
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
    public List<ProtocolMessage> getReceivedMessages() {
        return messages;
    }

    @Override
    public List<Record> getReceivedRecords() {
        return records;
    }

    @Override
    public List<DtlsHandshakeMessageFragment> getReceivedFragments() {
        return fragments;
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
    public void normalize() {
        super.normalize();
    }

    @Override
    public void normalize(TlsAction defaultAction) {
        super.normalize(defaultAction);
    }

    @Override
    public void filter() {
        super.filter();
    }

    @Override
    public void filter(TlsAction defaultCon) {
        super.filter(defaultCon);
    }

    @Override
    public List<ProtocolMessageType> getGoingToReceiveProtocolMessageTypes() {
        return new ArrayList<ProtocolMessageType>() {
            {
                add(waitTillMessage.getProtocolMessageType());
            }
        };
    }

    @Override
    public List<HandshakeMessageType> getGoingToReceiveHandshakeMessageTypes() {
        if (!waitTillMessage.isHandshakeMessage()) {
            return new ArrayList<>();
        }
        return new ArrayList<HandshakeMessageType>() {
            {
                add(((HandshakeMessage) waitTillMessage).getHandshakeMessageType());
            }
        };
    }

    @Override
    protected void distinctReceive(TlsContext tlsContext) {
        receiveTill(tlsContext, waitTillMessage);
    }

    @Override
    public List<ProtocolMessage> getExpectedMessages() {
        return Arrays.asList(waitTillMessage);
    }

    @Override
    public List<HttpMessage> getReceivedHttpMessages() {
        return httpMessages;
    }
}
