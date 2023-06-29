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
import de.rub.nds.tlsattacker.core.layer.LayerProcessingResult;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.*;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import jakarta.xml.bind.annotation.XmlElementRef;
import jakarta.xml.bind.annotation.XmlElementWrapper;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@XmlRootElement
public class ReceiveAction extends CommonReceiveAction implements ReceivingAction {

    private static final Logger LOGGER = LogManager.getLogger();

    @HoldsModifiableVariable @XmlElementWrapper @XmlElementRef
    protected List<ProtocolMessage> expectedMessages = new ArrayList<>();

    @HoldsModifiableVariable @XmlElementWrapper @XmlElementRef
    protected List<HttpMessage> expectedHttpMessages = new ArrayList<>();

    public ReceiveAction() {
        super();
    }

    public ReceiveAction(List<ProtocolMessage> expectedMessages) {
        super();
        this.expectedMessages = expectedMessages;
    }

    public ReceiveAction(ProtocolMessage... expectedMessages) {
        super();
        this.expectedMessages = new ArrayList(Arrays.asList(expectedMessages));
    }

    public ReceiveAction(
            List<ProtocolMessage> expectedMessages, List<HttpMessage> expectedHttpMessages) {
        this(expectedMessages);
        this.expectedHttpMessages = expectedHttpMessages;
    }

    public ReceiveAction(HttpMessage... expectedHttpMessages) {
        this.expectedHttpMessages = new ArrayList(Arrays.asList(expectedHttpMessages));
    }

    public ReceiveAction(Set<ActionOption> myActionOptions, List<ProtocolMessage> messages) {
        this(messages);
        setActionOptions(myActionOptions);
    }

    public ReceiveAction(Set<ActionOption> actionOptions, ProtocolMessage... messages) {
        this(actionOptions, new ArrayList(Arrays.asList(messages)));
    }

    public ReceiveAction(ActionOption actionOption, List<ProtocolMessage> messages) {
        this(messages);
        HashSet myActionOptions = new HashSet();
        myActionOptions.add(actionOption);
        setActionOptions(myActionOptions);
    }

    public ReceiveAction(ActionOption actionOption, ProtocolMessage... messages) {
        this(actionOption, new ArrayList<>(Arrays.asList(messages)));
    }

    public ReceiveAction(String connectionAlias) {
        super(connectionAlias);
    }

    public ReceiveAction(String connectionAliasAlias, List<ProtocolMessage> messages) {
        super(connectionAliasAlias);
        this.expectedMessages = messages;
    }

    public ReceiveAction(String connectionAliasAlias, ProtocolMessage... messages) {
        this(connectionAliasAlias, new ArrayList<>(Arrays.asList(messages)));
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder("Receive Action:\n");

        sb.append("\tExpected:");
        if ((expectedMessages != null)) {
            for (ProtocolMessage message : expectedMessages) {
                sb.append(message.toCompactString());
                sb.append(", ");
            }
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
        if ((expectedMessages != null) && (!expectedMessages.isEmpty())) {
            sb.append(" (");
            for (ProtocolMessage message : expectedMessages) {
                sb.append(message.toCompactString());
                sb.append(",");
            }
            sb.deleteCharAt(sb.lastIndexOf(",")).append(")");
        } else {
            sb.append(" (no messages set)");
        }
        return sb.toString();
    }

    @Override
    public boolean executedAsPlanned() {
        if (getLayerStackProcessingResult() != null) {
            for (LayerProcessingResult result :
                    getLayerStackProcessingResult().getLayerProcessingResultList()) {
                if (!result.isExecutedAsPlanned()) {
                    return false;
                }
            }
            return true;
        }
        return false;
    }

    @Override
    public List<ProtocolMessage> getExpectedMessages() {
        return expectedMessages;
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

    public void setExpectedMessages(List<ProtocolMessage> expectedMessages) {
        this.expectedMessages = expectedMessages;
    }

    public void setExpectedMessages(ProtocolMessage... expectedMessages) {
        this.expectedMessages = new ArrayList(Arrays.asList(expectedMessages));
    }

    @Override
    public void reset() {
        messages = null;
        records = null;
        fragments = null;
        setExecuted(false);
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
        hash = 67 * hash + Objects.hashCode(this.expectedMessages);
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
        final ReceiveAction other = (ReceiveAction) obj;
        if (!Objects.equals(this.expectedMessages, other.expectedMessages)) {
            return false;
        }
        if (!Objects.equals(this.messages, other.messages)) {
            return false;
        }
        if (!Objects.equals(this.records, other.records)) {
            return false;
        }
        if (!Objects.equals(this.fragments, other.fragments)) {
            return false;
        }
        return super.equals(obj);
    }

    @Override
    public void normalize() {
        super.normalize();
        initEmptyLists();
    }

    @Override
    public void normalize(TlsAction defaultAction) {
        super.normalize(defaultAction);
        initEmptyLists();
    }

    @Override
    public void filter() {
        super.filter();
        filterEmptyLists();
    }

    @Override
    public void filter(TlsAction defaultCon) {
        super.filter(defaultCon);
        filterEmptyLists();
    }

    private void filterEmptyLists() {
        if (expectedMessages == null || expectedMessages.isEmpty()) {
            expectedMessages = null;
        }
        if (expectedHttpMessages == null || expectedHttpMessages.isEmpty()) {
            expectedHttpMessages = null;
        }
    }

    private void initEmptyLists() {
        if (expectedMessages == null) {
            expectedMessages = new ArrayList<>();
        }
        if (expectedHttpMessages == null) {
            expectedHttpMessages = new ArrayList<>();
        }
    }

    @Override
    public List<ProtocolMessageType> getGoingToReceiveProtocolMessageTypes() {
        List<ProtocolMessageType> protocolMessageTypes = new ArrayList<>();
        for (ProtocolMessage msg : expectedMessages) {
            protocolMessageTypes.add(msg.getProtocolMessageType());
        }
        return protocolMessageTypes;
    }

    @Override
    public List<HandshakeMessageType> getGoingToReceiveHandshakeMessageTypes() {
        List<HandshakeMessageType> handshakeMessageTypes = new ArrayList<>();
        for (ProtocolMessage msg : expectedMessages) {
            if (msg instanceof HandshakeMessage) {
                handshakeMessageTypes.add(((HandshakeMessage) msg).getHandshakeMessageType());
            }
        }
        return handshakeMessageTypes;
    }

    @Override
    protected void distinctReceive(TlsContext tlsContext) {
        receive(tlsContext, expectedMessages, fragments, records, httpMessages);
    }

    @Override
    public List<HttpMessage> getReceivedHttpMessages() {
        return httpMessages;
    }
}
