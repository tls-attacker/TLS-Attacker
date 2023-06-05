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
import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.core.http.HttpMessage;
import de.rub.nds.tlsattacker.core.layer.*;
import de.rub.nds.tlsattacker.core.layer.constant.ImplementedLayers;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.state.State;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlElementRef;
import jakarta.xml.bind.annotation.XmlElementWrapper;
import jakarta.xml.bind.annotation.XmlElements;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.XmlTransient;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@XmlRootElement
public class ForwardMessagesAction extends TlsAction implements ReceivingAction, SendingAction {

    private static final Logger LOGGER = LogManager.getLogger();

    @XmlElement(name = "from")
    protected String receiveFromAlias = null;

    @XmlElement(name = "to")
    protected String forwardToAlias = null;

    @XmlTransient protected Boolean executedAsPlanned = null;

    /** If you want true here, use the more verbose ForwardMessagesWithPrepareAction. */
    @XmlTransient protected Boolean withPrepare = false;

    @HoldsModifiableVariable @XmlElementWrapper @XmlElementRef
    protected List<ProtocolMessage> receivedMessages;

    @HoldsModifiableVariable
    @XmlElementWrapper
    @XmlElements(value = {@XmlElement(type = Record.class, name = "Record")})
    protected List<Record> receivedRecords;

    @HoldsModifiableVariable
    @XmlElementWrapper
    @XmlElements(
            value = {@XmlElement(type = DtlsHandshakeMessageFragment.class, name = "DtlsFragment")})
    protected List<DtlsHandshakeMessageFragment> receivedFragments;

    @XmlElementWrapper @HoldsModifiableVariable @XmlElementRef
    protected List<ProtocolMessage> messages;

    @HoldsModifiableVariable
    @XmlElementWrapper
    @XmlElements(value = {@XmlElement(type = Record.class, name = "Record")})
    protected List<Record> records;

    @HoldsModifiableVariable
    @XmlElementWrapper
    @XmlElements(
            value = {@XmlElement(type = DtlsHandshakeMessageFragment.class, name = "DtlsFragment")})
    protected List<DtlsHandshakeMessageFragment> fragments;

    @HoldsModifiableVariable @XmlElementWrapper @XmlElementRef
    protected List<ProtocolMessage> sendMessages;

    @HoldsModifiableVariable
    @XmlElementWrapper
    @XmlElements(value = {@XmlElement(type = Record.class, name = "Record")})
    protected List<Record> sendRecords;

    @HoldsModifiableVariable
    @XmlElementWrapper
    @XmlElements(
            value = {@XmlElement(type = DtlsHandshakeMessageFragment.class, name = "DtlsFragment")})
    protected List<DtlsHandshakeMessageFragment> sendFragments;

    public ForwardMessagesAction() {}

    public ForwardMessagesAction(
            String receiveFromAlias, String forwardToAlias, List<ProtocolMessage> messages) {
        this.messages = messages;
        this.receiveFromAlias = receiveFromAlias;
        this.forwardToAlias = forwardToAlias;
    }

    public ForwardMessagesAction(
            String receiveFromAlias, String forwardToAlias, ProtocolMessage... messages) {
        this(receiveFromAlias, forwardToAlias, new ArrayList<>(Arrays.asList(messages)));
    }

    public void setReceiveFromAlias(String receiveFromAlias) {
        this.receiveFromAlias = receiveFromAlias;
    }

    public void setForwardToAlias(String forwardToAlias) {
        this.forwardToAlias = forwardToAlias;
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        if (isExecuted()) {
            throw new ActionExecutionException("Action already executed!");
        }

        assertAliasesSetProperly();

        TlsContext receiveFromCtx = state.getContext(receiveFromAlias).getTlsContext();
        TlsContext forwardToCtx = state.getContext(forwardToAlias).getTlsContext();

        receiveMessages(receiveFromCtx);
        applyMessages(forwardToCtx);
        forwardMessages(forwardToCtx);
        setExecuted(true);
    }

    void receiveMessages(TlsContext receiveFromContext) {
        LOGGER.debug("Receiving Messages...");
        LayerStack layerStack = receiveFromContext.getLayerStack();

        LayerConfiguration messageConfiguration =
                new SpecificReceiveLayerConfiguration(ImplementedLayers.MESSAGE, messages);

        List<LayerConfiguration> layerConfigurationList =
                sortLayerConfigurations(layerStack, messageConfiguration);
        LayerStackProcessingResult processingResult;
        processingResult = layerStack.receiveData(layerConfigurationList);
        receivedMessages =
                new ArrayList<>(
                        processingResult
                                .getResultForLayer(ImplementedLayers.MESSAGE)
                                .getUsedContainers());
        if (receiveFromContext.getChooser().getSelectedProtocolVersion().isDTLS()) {
            receivedFragments =
                    new ArrayList<>(
                            processingResult
                                    .getResultForLayer(ImplementedLayers.DTLS_FRAGMENT)
                                    .getUsedContainers());
        }
        receivedRecords =
                new ArrayList<>(
                        processingResult
                                .getResultForLayer(ImplementedLayers.RECORD)
                                .getUsedContainers());
        String expected = getReadableString(receivedMessages);
        LOGGER.debug("Receive Expected (" + receiveFromAlias + "): " + expected);
        String received = getReadableString(receivedMessages);
        LOGGER.info("Received Messages (" + receiveFromAlias + "): " + received);

        executedAsPlanned = checkMessageListsEquals(messages, receivedMessages);
    }

    /**
     * Apply the contents of the messages to the given TLS context.
     *
     * @param ctx
     */
    private void applyMessages(TlsContext ctx) {
        for (ProtocolMessage msg : receivedMessages) {
            LOGGER.debug("Applying " + msg.toCompactString() + " to forward context " + ctx);
            ProtocolMessageHandler h = msg.getHandler(ctx);
            h.adjustContext(msg);
        }
    }

    private void forwardMessages(TlsContext forwardToCtx) {
        LOGGER.info("Forwarding messages (" + forwardToAlias + "): " + getReadableString(messages));
        try {
            LayerStack layerStack = forwardToCtx.getLayerStack();

            LayerConfiguration dtlsConfiguration =
                    new SpecificSendLayerConfiguration<>(
                            ImplementedLayers.DTLS_FRAGMENT, receivedFragments);
            LayerConfiguration messageConfiguration =
                    new SpecificSendLayerConfiguration<>(
                            ImplementedLayers.MESSAGE, receivedMessages);
            LayerConfiguration recordConfiguration =
                    new SpecificSendLayerConfiguration<>(ImplementedLayers.RECORD, receivedRecords);

            List<LayerConfiguration> layerConfigurationList =
                    sortLayerConfigurations(
                            layerStack,
                            dtlsConfiguration,
                            messageConfiguration,
                            recordConfiguration);
            LayerStackProcessingResult processingResult =
                    layerStack.sendData(layerConfigurationList);

            sendMessages =
                    new ArrayList<>(
                            processingResult
                                    .getResultForLayer(ImplementedLayers.MESSAGE)
                                    .getUsedContainers());
            if (forwardToCtx.getChooser().getSelectedProtocolVersion().isDTLS()) {
                sendFragments =
                        new ArrayList<>(
                                processingResult
                                        .getResultForLayer(ImplementedLayers.DTLS_FRAGMENT)
                                        .getUsedContainers());
            }
            sendRecords =
                    new ArrayList<>(
                            processingResult
                                    .getResultForLayer(ImplementedLayers.RECORD)
                                    .getUsedContainers());

            executedAsPlanned = checkMessageListsEquals(sendMessages, receivedMessages);

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
    private boolean checkMessageListsEquals(
            List<ProtocolMessage> expectedMessages, List<ProtocolMessage> actualMessages) {
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
    public List<Record> getReceivedRecords() {
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
    public List<Record> getSendRecords() {
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
     * TODO: the equals methods for message/record actions and similar classes would require that
     * messages and records implement equals for a proper implementation. The present approach is
     * not satisfying.
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
            throw new ActionExecutionException(
                    "Can't execute "
                            + this.getClass().getSimpleName()
                            + " with empty receive alias (if using XML: add <from/>)");
        }
        if ((forwardToAlias == null) || (forwardToAlias.isEmpty())) {
            throw new ActionExecutionException(
                    "Can't execute "
                            + this.getClass().getSimpleName()
                            + " with empty forward alias (if using XML: add <to/>)");
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
            types.add(msg.getProtocolMessageType());
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

    @Override
    public List<HttpMessage> getReceivedHttpMessages() {
        // ForwardMessages should not interfere with messages above TLS
        return new LinkedList<>();
    }
}
