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
import de.rub.nds.tlsattacker.core.constants.AlertLevel;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.https.HttpsRequestMessage;
import de.rub.nds.tlsattacker.core.https.HttpsResponseMessage;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.*;
import de.rub.nds.tlsattacker.core.record.AbstractRecord;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import de.rub.nds.tlsattacker.core.workflow.action.executor.MessageActionResult;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlElementRef;
import javax.xml.bind.annotation.XmlElementWrapper;
import javax.xml.bind.annotation.XmlElements;
import javax.xml.bind.annotation.XmlRootElement;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@XmlRootElement
public class ReceiveAction extends MessageAction implements ReceivingAction {

    private static final Logger LOGGER = LogManager.getLogger();

    @HoldsModifiableVariable
    @XmlElementWrapper
    @XmlElementRef
    protected List<ProtocolMessage> expectedMessages = new ArrayList<>();

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
    public void execute(State state) throws WorkflowExecutionException {
        TlsContext tlsContext = state.getTlsContext(getConnectionAlias());

        if (isExecuted()) {
            throw new WorkflowExecutionException("Action already executed!");
        }

        LOGGER.debug("Receiving Messages...");
        MessageActionResult result = receiveMessageHelper.receiveMessages(expectedMessages, tlsContext);
        records = new ArrayList<>(result.getRecordList());
        messages = new ArrayList<>(result.getMessageList());
        if (result.getMessageFragmentList() != null) {
            fragments = new ArrayList<>(result.getMessageFragmentList());
        }
        setExecuted(true);

        String expected = getReadableString(expectedMessages);
        LOGGER.debug("Receive Expected:" + expected);
        String received = getReadableString(messages);
        if (hasDefaultAlias()) {
            LOGGER.info("Received Messages: " + received);
        } else {
            LOGGER.info("Received Messages (" + getConnectionAlias() + "): " + received);
        }
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
        return receivedAsPlanned(getMessages(), getExpectedMessages(), getActionOptions());
    }

    public static boolean receivedAsPlanned(List<ProtocolMessage> messages, List<ProtocolMessage> expectedMessages) {
        return receivedAsPlanned(messages, expectedMessages, new HashSet<>());
    }

    public static boolean receivedAsPlanned(List<ProtocolMessage> messages, List<ProtocolMessage> expectedMessages,
        Set<ActionOption> actionOptions) {
        if (messages == null) {
            return false;
        }
        int j = 0;
        for (int i = 0; i < expectedMessages.size(); i++) {
            if (j >= messages.size() && expectedMessages.get(i).isRequired()) {
                return false;
            } else if (j < messages.size()) {
                if (!Objects.equals(expectedMessages.get(i).getClass(), messages.get(j).getClass())
                    && expectedMessages.get(i).isRequired()) {
                    if (receivedMessageCanBeIgnored(messages.get(j), actionOptions)) {
                        j++;
                        i--;
                    } else {
                        return false;
                    }

                } else if (Objects.equals(expectedMessages.get(i).getClass(), messages.get(j).getClass())) {
                    j++;
                }
            }
        }

        for (; j < messages.size(); j++) {
            if (!receivedMessageCanBeIgnored(messages.get(j), actionOptions)
                && !actionOptions.contains(ActionOption.CHECK_ONLY_EXPECTED)) {
                return false; // additional messages are not allowed
            }
        }

        return true;
    }

    public List<ProtocolMessage> getExpectedMessages() {
        return expectedMessages;
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
    }

    private void initEmptyLists() {
        if (expectedMessages == null) {
            expectedMessages = new ArrayList<>();

        }
    }

    private static boolean receivedMessageCanBeIgnored(ProtocolMessage msg, Set<ActionOption> actionOptions) {
        if (actionOptions.contains(ActionOption.IGNORE_UNEXPECTED_WARNINGS) && msg instanceof AlertMessage) {
            AlertMessage alert = (AlertMessage) msg;
            if (alert.getLevel().getOriginalValue() == AlertLevel.WARNING.getValue()) {
                return true;
            }
        } else if (actionOptions.contains(ActionOption.IGNORE_UNEXPECTED_NEW_SESSION_TICKETS)
            && msg instanceof NewSessionTicketMessage) {
            return true;
        } else if (actionOptions.contains(ActionOption.IGNORE_UNEXPECTED_KEY_UPDATE_MESSAGES)
            && msg instanceof KeyUpdateMessage) {
            return true;
        } else if (actionOptions.contains(ActionOption.IGNORE_UNEXPECTED_APP_DATA)
            && msg instanceof ApplicationMessage) {
            return true;
        } else if (actionOptions.contains(ActionOption.IGNORE_UNEXPECTED_HTTPS_MESSAGES)
            && (msg instanceof HttpsResponseMessage || msg instanceof HttpsRequestMessage)) {
            return true;
        }

        return false;
    }

    @Override
    public MessageActionDirection getMessageDirection() {
        return MessageActionDirection.RECEIVING;
    }

    @Override
    public List<ProtocolMessageType> getGoingToReceiveProtocolMessageTypes() {
        List<ProtocolMessageType> protocolMessageTypes = new ArrayList<>();
        for (ProtocolMessage msg : expectedMessages) {
            if (!(msg instanceof TlsMessage)) {
                continue;
            }
            protocolMessageTypes.add(((TlsMessage) msg).getProtocolMessageType());
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
}
