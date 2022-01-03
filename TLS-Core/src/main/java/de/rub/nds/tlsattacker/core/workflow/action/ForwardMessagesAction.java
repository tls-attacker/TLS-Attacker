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
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.https.HttpsRequestMessage;
import de.rub.nds.tlsattacker.core.https.HttpsResponseMessage;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.core.protocol.message.*;
import de.rub.nds.tlsattacker.core.record.AbstractRecord;
import de.rub.nds.tlsattacker.core.record.BlobRecord;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.action.executor.MessageActionResult;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ReceiveMessageHelper;
import de.rub.nds.tlsattacker.core.workflow.action.executor.SendMessageHelper;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlElementRef;
import javax.xml.bind.annotation.XmlElementWrapper;
import javax.xml.bind.annotation.XmlElements;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlTransient;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@XmlRootElement
public class ForwardMessagesAction extends TlsAction implements ReceivingAction, SendingAction {

    private static final Logger LOGGER = LogManager.getLogger();

    @XmlElement(name = "from")
    protected String receiveFromAlias = null;
    @XmlElement(name = "to")
    protected String forwardToAlias = null;

    @XmlTransient
    protected Boolean executedAsPlanned = null;

    /**
     * If you want true here, use the more verbose ForwardMessagesWithPrepareAction.
     */
    @XmlTransient
    protected Boolean withPrepare = false;

    @HoldsModifiableVariable
    @XmlElementWrapper
    @XmlElementRef
    protected List<ProtocolMessage> receivedMessages;

    @HoldsModifiableVariable
    @XmlElementWrapper
    @XmlElements(value = { @XmlElement(type = Record.class, name = "Record"),
        @XmlElement(type = BlobRecord.class, name = "BlobRecord") })
    protected List<AbstractRecord> receivedRecords;

    @HoldsModifiableVariable
    @XmlElementWrapper
    @XmlElements(value = { @XmlElement(type = DtlsHandshakeMessageFragment.class, name = "DtlsFragment") })
    protected List<DtlsHandshakeMessageFragment> receivedFragments;

    @XmlElementWrapper
    @HoldsModifiableVariable
    @XmlElementRef
    protected List<ProtocolMessage> messages;

    @HoldsModifiableVariable
    @XmlElementWrapper
    @XmlElements(value = { @XmlElement(type = Record.class, name = "Record"),
        @XmlElement(type = BlobRecord.class, name = "BlobRecord") })
    protected List<AbstractRecord> records;

    @HoldsModifiableVariable
    @XmlElementWrapper
    @XmlElements(value = { @XmlElement(type = DtlsHandshakeMessageFragment.class, name = "DtlsFragment") })
    protected List<DtlsHandshakeMessageFragment> fragments;

    @HoldsModifiableVariable
    @XmlElementWrapper
    @XmlElementRef
    protected List<ProtocolMessage> sendMessages;

    @HoldsModifiableVariable
    @XmlElementWrapper
    @XmlElements(value = { @XmlElement(type = Record.class, name = "Record"),
        @XmlElement(type = BlobRecord.class, name = "BlobRecord") })
    protected List<AbstractRecord> sendRecords;

    @HoldsModifiableVariable
    @XmlElementWrapper
    @XmlElements(value = { @XmlElement(type = DtlsHandshakeMessageFragment.class, name = "DtlsFragment") })
    protected List<DtlsHandshakeMessageFragment> sendFragments;

    @XmlTransient
    protected ReceiveMessageHelper receiveMessageHelper;

    @XmlTransient
    protected SendMessageHelper sendMessageHelper;

    public ForwardMessagesAction() {
        this.receiveMessageHelper = new ReceiveMessageHelper();
        this.sendMessageHelper = new SendMessageHelper();
    }

    public ForwardMessagesAction(String receiveFromAlias, String forwardToAlias) {
        this(receiveFromAlias, forwardToAlias, new ReceiveMessageHelper());
    }

    /**
     * Allow to pass a fake ReceiveMessageHelper helper for testing.
     */
    protected ForwardMessagesAction(String receiveFromAlias, String forwardToAlias,
        ReceiveMessageHelper receiveMessageHelper) {
        this.receiveFromAlias = receiveFromAlias;
        this.forwardToAlias = forwardToAlias;
        this.receiveMessageHelper = receiveMessageHelper;
        this.sendMessageHelper = new SendMessageHelper();
    }

    public ForwardMessagesAction(String receiveFromAlias, String forwardToAlias, List<ProtocolMessage> messages) {
        this.messages = messages;
        this.receiveFromAlias = receiveFromAlias;
        this.forwardToAlias = forwardToAlias;
        this.receiveMessageHelper = new ReceiveMessageHelper();
        this.sendMessageHelper = new SendMessageHelper();
    }

    public ForwardMessagesAction(String receiveFromAlias, String forwardToAlias, ProtocolMessage... messages) {
        this(receiveFromAlias, forwardToAlias, new ArrayList<>(Arrays.asList(messages)));
    }

    public void setReceiveFromAlias(String receiveFromAlias) {
        this.receiveFromAlias = receiveFromAlias;
    }

    public void setForwardToAlias(String forwardToAlias) {
        this.forwardToAlias = forwardToAlias;
    }

    @Override
    public void execute(State state) throws WorkflowExecutionException {
        if (isExecuted()) {
            throw new WorkflowExecutionException("Action already executed!");
        }

        assertAliasesSetProperly();

        TlsContext receiveFromCtx = state.getTlsContext(receiveFromAlias);
        TlsContext forwardToCtx = state.getTlsContext(forwardToAlias);

        receiveMessages(receiveFromCtx);
        applyMessages(forwardToCtx);
        forwardMessages(forwardToCtx);
    }

    void receiveMessages(TlsContext receiveFromCtx) {
        LOGGER.debug("Receiving Messages...");
        MessageActionResult result = receiveMessageHelper.receiveMessages(messages, receiveFromCtx);
        receivedRecords = result.getRecordList();
        receivedMessages = result.getMessageList();
        if (result.getMessageFragmentList() != null) {
            receivedFragments = new ArrayList<>(result.getMessageFragmentList());
        }
        String expected = getReadableString(receivedMessages);
        LOGGER.debug("Receive Expected (" + receiveFromAlias + "): " + expected);
        String received = getReadableString(receivedMessages);
        LOGGER.info("Received Messages (" + receiveFromAlias + "): " + received);

        executedAsPlanned = checkMessageListsEquals(messages, receivedMessages);
    }

    /**
     * Apply the contents of the messages to the given TLS context.
     *
     * @param protocolMessages
     * @param tlsContext
     */
    private void applyMessages(TlsContext ctx) {
        for (ProtocolMessage msg : receivedMessages) {
            LOGGER.debug("Applying " + msg.toCompactString() + " to forward context " + ctx);
            ProtocolMessageHandler<ProtocolMessage> h = msg.getHandler(ctx);
            h.adjustContext(msg);
        }
    }

    private void forwardMessages(TlsContext forwardToCtx) {
        LOGGER.info("Forwarding messages (" + forwardToAlias + "): " + getReadableString(messages));
        try {
            MessageActionResult result = sendMessageHelper.sendMessages(receivedMessages, receivedFragments,
                receivedRecords, forwardToCtx, withPrepare);
            sendMessages = result.getMessageList();
            sendRecords = result.getRecordList();
            if (result.getMessageFragmentList() != null) {
                sendFragments = new ArrayList<>(result.getMessageFragmentList());
            }
            if (executedAsPlanned) {
                executedAsPlanned = checkMessageListsEquals(sendMessages, messages);
            }
            setExecuted(true);
        } catch (IOException e) {
            LOGGER.debug(e);
            executedAsPlanned = false;
            setExecuted(false);
        }
    }

    public String getReceiveFromAlias() {
        return receiveFromAlias;
    }

    public String getForwardToAlias() {
        return forwardToAlias;
    }

    // TODO: yes, the correct way would be implement equals() for all
    // ProtocolMessages...
    private boolean checkMessageListsEquals(List<ProtocolMessage> expectedMessages,
        List<ProtocolMessage> actualMessages) {
        boolean actualEmpty = true;
        boolean expectedEmpty = true;
        if (actualMessages != null && !actualMessages.isEmpty()) {
            actualEmpty = false;
        }
        if (expectedMessages != null && !expectedMessages.isEmpty()) {
            expectedEmpty = false;
        }
        if (actualEmpty == expectedEmpty) {
            return true;
        }
        if (actualEmpty != expectedEmpty) {
            return false;
        }
        if (actualMessages.size() != expectedMessages.size()) {
            return false;
        } else {
            for (int i = 0; i < actualMessages.size(); i++) {
                if (!actualMessages.get(i).getClass().equals(expectedMessages.get(i).getClass())) {
                    return false;
                }
            }
        }
        return true;
    }

    @Override
    public boolean executedAsPlanned() {
        return executedAsPlanned;
    }

    @Override
    public void reset() {
        receivedMessages = null;
        receivedRecords = null;
        receivedFragments = null;
        sendMessages = null;
        sendRecords = null;
        sendFragments = null;
        executedAsPlanned = false;
        setExecuted(null);
    }

    @Override
    public List<ProtocolMessage> getReceivedMessages() {
        return receivedMessages;
    }

    @Override
    public List<AbstractRecord> getReceivedRecords() {
        return receivedRecords;
    }

    @Override
    public List<DtlsHandshakeMessageFragment> getReceivedFragments() {
        return receivedFragments;
    }

    @Override
    public List<ProtocolMessage> getSendMessages() {
        return sendMessages;
    }

    @Override
    public List<AbstractRecord> getSendRecords() {
        return sendRecords;
    }

    @Override
    public List<DtlsHandshakeMessageFragment> getSendFragments() {
        return sendFragments;
    }

    public List<ProtocolMessage> getMessages() {
        return messages;
    }

    public void setMessages(List<ProtocolMessage> messages) {
        this.messages = messages;
    }

    public void setMessages(ProtocolMessage... messages) {
        this.messages = new ArrayList(Arrays.asList(messages));
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 89 * hash + Objects.hashCode(this.receiveFromAlias);
        hash = 89 * hash + Objects.hashCode(this.forwardToAlias);
        hash = 89 * hash + Objects.hashCode(this.executedAsPlanned);
        hash = 89 * hash + Objects.hashCode(this.receivedMessages);
        hash = 89 * hash + Objects.hashCode(this.receivedRecords);
        hash = 89 * hash + Objects.hashCode(this.receivedFragments);
        hash = 89 * hash + Objects.hashCode(this.sendMessages);
        hash = 89 * hash + Objects.hashCode(this.sendRecords);
        hash = 89 * hash + Objects.hashCode(this.messages);
        hash = 89 * hash + Objects.hashCode(this.records);
        hash = 89 * hash + Objects.hashCode(this.fragments);
        return hash;
    }

    /**
     * TODO: the equals methods for message/record actions and similar classes would require that messages and records
     * implement equals for a proper implementation. The present approach is not satisfying.
     */
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
        final ForwardMessagesAction other = (ForwardMessagesAction) obj;
        if (!Objects.equals(this.receiveFromAlias, other.receiveFromAlias)) {
            return false;
        }
        if (!Objects.equals(this.forwardToAlias, other.forwardToAlias)) {
            return false;
        }
        if (!Objects.equals(this.executedAsPlanned, other.executedAsPlanned)) {
            return false;
        }
        if (!checkMessageListsEquals(this.receivedMessages, other.receivedMessages)) {
            return false;
        }
        if (!Objects.equals(this.receivedRecords, other.receivedRecords)) {
            return false;
        }
        if (!Objects.equals(this.receivedFragments, other.receivedFragments)) {
            return false;
        }
        if (!checkMessageListsEquals(this.sendMessages, other.sendMessages)) {
            return false;
        }
        if (!Objects.equals(this.sendRecords, other.sendRecords)) {
            return false;
        }
        if (!Objects.equals(this.sendFragments, other.sendFragments)) {
            return false;
        }
        if (!checkMessageListsEquals(this.messages, other.messages)) {
            return false;
        }
        return Objects.equals(this.records, other.records);
    }

    @Override
    public Set<String> getAllAliases() {
        Set<String> aliases = new LinkedHashSet<>();
        aliases.add(forwardToAlias);
        aliases.add(receiveFromAlias);
        return aliases;
    }

    @Override
    public void assertAliasesSetProperly() throws ConfigurationException {
        if ((receiveFromAlias == null) || (receiveFromAlias.isEmpty())) {
            throw new WorkflowExecutionException("Can't execute " + this.getClass().getSimpleName()
                + " with empty receive alias (if using XML: add <from/>)");
        }
        if ((forwardToAlias == null) || (forwardToAlias.isEmpty())) {
            throw new WorkflowExecutionException("Can't execute " + this.getClass().getSimpleName()
                + " with empty forward alis (if using XML: add <to/>)");
        }
    }

    public String getReadableString(List<ProtocolMessage> messages) {
        return getReadableString(messages, false);
    }

    public String getReadableString(List<ProtocolMessage> messages, Boolean verbose) {
        StringBuilder builder = new StringBuilder();
        if (messages == null) {
            return builder.toString();
        }
        for (ProtocolMessage message : messages) {
            if (verbose) {
                builder.append(message.toString());
            } else {
                builder.append(message.toCompactString());
            }
            if (!message.isRequired()) {
                builder.append("*");
            }
            builder.append(", ");
        }
        return builder.toString();
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
        stripEmptyLists();
    }

    @Override
    public void filter(TlsAction defaultAction) {
        super.filter(defaultAction);
        stripEmptyLists();
    }

    private void stripEmptyLists() {
        if (messages == null || messages.isEmpty()) {
            messages = null;
        }
        if (records == null || records.isEmpty()) {
            records = null;
        }
        if (fragments == null || fragments.isEmpty()) {
            fragments = null;
        }
        if (receivedMessages == null || receivedMessages.isEmpty()) {
            receivedMessages = null;
        }
        if (receivedRecords == null || receivedRecords.isEmpty()) {
            receivedRecords = null;
        }
        if (receivedFragments == null || receivedFragments.isEmpty()) {
            receivedFragments = null;
        }
        if (sendMessages == null || sendMessages.isEmpty()) {
            sendMessages = null;
        }
        if (sendRecords == null || sendRecords.isEmpty()) {
            sendRecords = null;
        }
        if (sendFragments == null || sendFragments.isEmpty()) {
            sendFragments = null;
        }
    }

    private void initEmptyLists() {
        if (messages == null) {
            messages = new ArrayList<>();
        }
        if (records == null) {
            records = new ArrayList<>();
        }
        if (fragments == null) {
            fragments = new ArrayList<>();
        }
        if (receivedMessages == null) {
            receivedMessages = new ArrayList<>();
        }
        if (receivedRecords == null) {
            receivedRecords = new ArrayList<>();
        }
        if (receivedFragments == null) {
            receivedFragments = new ArrayList<>();
        }
        if (sendMessages == null) {
            sendMessages = new ArrayList<>();
        }
        if (sendRecords == null) {
            sendRecords = new ArrayList<>();
        }
        if (sendFragments == null) {
            sendFragments = new ArrayList<>();
        }
    }

    @Override
    public List<ProtocolMessageType> getGoingToReceiveProtocolMessageTypes() {
        if (this.messages == null) {
            return new ArrayList<>();
        }

        List<ProtocolMessageType> types = new ArrayList<>();
        for (ProtocolMessage msg : messages) {
            if (!(msg instanceof TlsMessage)) {
                continue;
            }
            types.add(((TlsMessage) msg).getProtocolMessageType());
        }
        return types;
    }

    @Override
    public List<HandshakeMessageType> getGoingToReceiveHandshakeMessageTypes() {
        if (this.messages == null) {
            return new ArrayList<>();
        }

        List<HandshakeMessageType> types = new ArrayList<>();
        for (ProtocolMessage msg : messages) {
            if (!(msg instanceof HandshakeMessage)) {
                continue;
            }
            types.add(((HandshakeMessage) msg).getHandshakeMessageType());
        }
        return types;
    }

    @Override
    public List<ProtocolMessageType> getGoingToSendProtocolMessageTypes() {
        return this.getGoingToReceiveProtocolMessageTypes();
    }

    @Override
    public List<HandshakeMessageType> getGoingToSendHandshakeMessageTypes() {
        return this.getGoingToReceiveHandshakeMessageTypes();
    }
}
