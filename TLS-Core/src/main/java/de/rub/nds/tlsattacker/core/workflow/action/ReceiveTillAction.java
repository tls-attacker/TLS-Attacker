/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.https.HttpsRequestMessage;
import de.rub.nds.tlsattacker.core.https.HttpsResponseMessage;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.*;
import de.rub.nds.tlsattacker.core.record.AbstractRecord;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.action.executor.MessageActionResult;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlElementRef;
import javax.xml.bind.annotation.XmlElements;
import javax.xml.bind.annotation.XmlRootElement;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@XmlRootElement
public class ReceiveTillAction extends MessageAction implements ReceivingAction {

    private static final Logger LOGGER = LogManager.getLogger();

    @HoldsModifiableVariable
    @XmlElementRef
    protected TlsMessage waitTillMessage;

    public ReceiveTillAction() {
        super();
    }

    public ReceiveTillAction(TlsMessage waitTillMessage) {
        super();
        this.waitTillMessage = waitTillMessage;
    }

    public ReceiveTillAction(String connectionAliasAlias, TlsMessage waitTillMessage) {
        super(connectionAliasAlias);
        this.waitTillMessage = waitTillMessage;
    }

    @Override
    public void execute(State state) throws WorkflowExecutionException {
        TlsContext tlsContext = state.getTlsContext(getConnectionAlias());

        if (isExecuted()) {
            throw new WorkflowExecutionException("Action already executed!");
        }

        LOGGER.debug("Receiving Messages...");
        MessageActionResult result = receiveMessageHelper.receiveMessagesTill(waitTillMessage, tlsContext);
        records = new ArrayList<>(result.getRecordList());
        messages = new ArrayList<>(result.getMessageList());
        if (result.getMessageFragmentList() != null) {
            fragments = new ArrayList<>(result.getMessageFragmentList());
        }
        setExecuted(true);

        String expected = getReadableString(waitTillMessage);
        LOGGER.debug("Receive message we waited for:" + expected);
        String received = getReadableString(messages);
        if (hasDefaultAlias()) {
            LOGGER.info("Received Messages: " + received);
        } else {
            LOGGER.info("Received Messages (" + getConnectionAlias() + "): " + received);
        }
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

    public TlsMessage getWaitTillMessage() {
        return waitTillMessage;
    }

    void setReceivedMessages(List<ProtocolMessage> receivedMessages) {
        this.messages = receivedMessages;
    }

    void setReceivedRecords(List<AbstractRecord> receivedRecords) {
        this.records = receivedRecords;
    }

    void setReceivedFragments(List<DtlsHandshakeMessageFragment> fragments) {
        this.fragments = fragments;
    }

    public void setWaitTillMessage(TlsMessage waitTillMessage) {
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
    public List<AbstractRecord> getReceivedRecords() {
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
    public MessageActionDirection getMessageDirection() {
        return MessageActionDirection.RECEIVING;
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
}
