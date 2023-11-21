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
import de.rub.nds.tlsattacker.core.http.HttpMessage;
import de.rub.nds.tlsattacker.core.layer.DataContainerFilter;
import de.rub.nds.tlsattacker.core.layer.GenericReceiveLayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.LayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.LayerStack;
import de.rub.nds.tlsattacker.core.layer.LayerStackProcessingResult;
import de.rub.nds.tlsattacker.core.layer.ReceiveLayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.ReceiveTillLayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.SpecificReceiveLayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.SpecificSendLayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.TightReceiveLayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.constant.ImplementedLayers;
import de.rub.nds.tlsattacker.core.layer.constant.LayerType;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.layer.data.DataContainer;
import de.rub.nds.tlsattacker.core.layer.impl.DataContainerFilters.GenericDataContainerFilter;
import de.rub.nds.tlsattacker.core.layer.impl.DataContainerFilters.Tls.WarningAlertFilter;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import de.rub.nds.tlsattacker.core.protocol.message.KeyUpdateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.NewSessionTicketMessage;
import de.rub.nds.tlsattacker.core.quic.frame.QuicFrame;
import de.rub.nds.tlsattacker.core.quic.packet.QuicPacket;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlElementRef;
import jakarta.xml.bind.annotation.XmlElementWrapper;
import jakarta.xml.bind.annotation.XmlElements;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.XmlTransient;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@XmlRootElement(name = "MessageAction")
public abstract class MessageAction extends ConnectionBoundAction {

    public enum MessageActionDirection {
        SENDING,
        RECEIVING
    }

    @XmlElementWrapper @HoldsModifiableVariable @XmlElementRef
    protected List<ProtocolMessage> messages = new ArrayList<>();

    @XmlElementWrapper
    @HoldsModifiableVariable
    @XmlElements(value = {@XmlElement(type = HttpMessage.class, name = "HttpMessage")})
    protected List<HttpMessage> httpMessages = new ArrayList<>();

    @HoldsModifiableVariable
    @XmlElementWrapper
    @XmlElements(value = {@XmlElement(type = Record.class, name = "Record")})
    protected List<Record> records = new ArrayList<>();

    @HoldsModifiableVariable
    @XmlElementWrapper
    @XmlElements(
            value = {@XmlElement(type = DtlsHandshakeMessageFragment.class, name = "DtlsFragment")})
    protected List<DtlsHandshakeMessageFragment> fragments = new ArrayList<>();

    @HoldsModifiableVariable @XmlElementWrapper @XmlElementRef
    protected List<QuicFrame> quicFrames = new ArrayList<>();

    @HoldsModifiableVariable @XmlElementWrapper @XmlElementRef
    protected List<QuicPacket> quicPackets = new ArrayList<>();

    @XmlTransient private LayerStackProcessingResult layerStackProcessingResult;

    public MessageAction() {}

    public MessageAction(
            List<ProtocolMessage> messages,
            List<QuicFrame> quicFrames,
            List<QuicPacket> quicPackets) {
        if (messages != null) {
            this.messages = messages;
        }
        if (quicFrames != null) {
            this.quicFrames = quicFrames;
        }
        if (quicPackets != null) {
            this.quicPackets = quicPackets;
        }
    }

    public MessageAction(List<ProtocolMessage> messages) {
        this.messages = new ArrayList<>(messages);
    }

    public MessageAction(QuicFrame... quicFrames) {
        this.quicFrames = new ArrayList<>(Arrays.asList(quicFrames));
    }

    public MessageAction(QuicPacket... quicPackets) {
        this.quicPackets = new ArrayList<>(Arrays.asList(quicPackets));
    }

    public MessageAction(ProtocolMessage... messages) {
        this.messages = new ArrayList<>(Arrays.asList(messages));
    }

    public MessageAction(String connectionAlias) {
        super(connectionAlias);
    }

    public MessageAction(String connectionAlias, List<ProtocolMessage> messages) {
        super(connectionAlias);
        this.messages = new ArrayList<>(messages);
    }

    public MessageAction(String connectionAlias, ProtocolMessage... messages) {
        this(connectionAlias, new ArrayList<>(Arrays.asList(messages)));
    }

    protected String getReadableStringFromContainerList(
            List<? extends DataContainer>... containerLists) {
        StringBuilder sb = new StringBuilder();
        String string =
                Stream.of(containerLists)
                        .filter(Objects::nonNull)
                        .flatMap(List::stream)
                        .filter(Objects::nonNull)
                        .map(DataContainer::toCompactString)
                        .collect(Collectors.joining(", "));
        if (!string.isEmpty()) {
            sb.append(" (").append(string).append(")");
        } else {
            sb.append(" (no messages/frames/packets)");
        }
        return sb.toString();
    }

    public String getReadableStringFromMessages(ProtocolMessage... messages) {
        return getReadableStringFromMessages(Arrays.asList(messages));
    }

    public String getReadableStringFromMessages(List<ProtocolMessage> messages) {
        return getReadableStringFromMessages(messages, false);
    }

    public String getReadableStringFromMessages(List<ProtocolMessage> messages, Boolean verbose) {
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

    public String getReadableStringFromQuicFrames(QuicFrame... frames) {
        return getReadableStringFromQuicFrames(Arrays.asList(frames));
    }

    public String getReadableStringFromQuicFrames(List<QuicFrame> messages) {
        return getReadableStringFromQuicFrames(messages, false);
    }

    public String getReadableStringFromQuicFrames(List<QuicFrame> quicFrames, Boolean verbose) {
        StringBuilder builder = new StringBuilder();
        if (quicFrames == null) {
            return builder.toString();
        }
        for (QuicFrame quicFrame : quicFrames) {
            if (verbose) {
                builder.append(quicFrame.toString());
            } else {
                builder.append(quicFrame.toCompactString());
            }
            if (!quicFrame.isRequired()) {
                builder.append("*");
            }
            builder.append(", ");
        }
        return builder.toString();
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

    public List<Record> getRecords() {
        return records;
    }

    public void setRecords(List<Record> records) {
        this.records = records;
    }

    public void setRecords(Record... records) {
        this.records = new ArrayList<>(Arrays.asList(records));
    }

    public List<QuicFrame> getQuicFrames() {
        return quicFrames;
    }

    public void setQuicFrames(List<QuicFrame> quicFrames) {
        this.quicFrames = quicFrames;
    }

    public void setQuicFrames(QuicFrame... frames) {
        this.quicFrames = new ArrayList<>(Arrays.asList(frames));
    }

    public List<QuicPacket> getQuicPackets() {
        return quicPackets;
    }

    public void setQuicPackets(List<QuicPacket> quicPackets) {
        this.quicPackets = quicPackets;
    }

    public void setPackets(QuicPacket... packets) {
        this.quicPackets = new ArrayList<>(Arrays.asList(packets));
    }

    public List<DtlsHandshakeMessageFragment> getFragments() {
        return fragments;
    }

    public void setFragments(List<DtlsHandshakeMessageFragment> fragments) {
        this.fragments = fragments;
    }

    public void setFragments(DtlsHandshakeMessageFragment... fragments) {
        this.fragments = new ArrayList<>(Arrays.asList(fragments));
    }

    public void clearRecords() {
        this.records = null;
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
        if (httpMessages == null || httpMessages.isEmpty()) {
            httpMessages = null;
        }
        if (quicFrames == null || quicFrames.isEmpty()) {
            quicFrames = null;
        }
        if (quicPackets == null || quicPackets.isEmpty()) {
            quicPackets = null;
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
        if (httpMessages == null) {
            httpMessages = new ArrayList<>();
        }
        if (quicFrames == null) {
            quicFrames = new ArrayList<>();
        }
        if (quicPackets == null) {
            quicPackets = new ArrayList<>();
        }
    }

    public boolean isSendingAction() {
        return this instanceof SendingAction;
    }

    public boolean isReceivingAction() {
        return this instanceof ReceivingAction;
    }

    protected void send(
            TlsContext tlsContext,
            List<ProtocolMessage> protocolMessagesToSend,
            List<DtlsHandshakeMessageFragment> fragmentsToSend,
            List<Record> recordsToSend,
            List<QuicFrame> framesToSend,
            List<QuicPacket> packetsToSend,
            List<HttpMessage> httpMessagesToSend)
            throws IOException {
        LayerStack layerStack = tlsContext.getLayerStack();

        LayerConfiguration dtlsConfiguration =
                new SpecificSendLayerConfiguration<>(
                        ImplementedLayers.DTLS_FRAGMENT, fragmentsToSend);
        LayerConfiguration messageConfiguration =
                new SpecificSendLayerConfiguration<>(
                        ImplementedLayers.MESSAGE, protocolMessagesToSend);
        LayerConfiguration ssl2Configuration =
                new SpecificSendLayerConfiguration(ImplementedLayers.SSL2, protocolMessagesToSend);
        LayerConfiguration recordConfiguration =
                new SpecificSendLayerConfiguration<>(ImplementedLayers.RECORD, recordsToSend);
        LayerConfiguration httpConfiguration =
                new SpecificSendLayerConfiguration<>(ImplementedLayers.HTTP, httpMessagesToSend);
        LayerConfiguration quicFrameConfiguration =
                new SpecificSendLayerConfiguration(ImplementedLayers.QUICFRAME, framesToSend);
        LayerConfiguration quicPacketConfiguration =
                new SpecificSendLayerConfiguration(ImplementedLayers.QUICPACKET, packetsToSend);

        checkLayerConsistency(layerStack, httpMessagesToSend);

        List<LayerConfiguration> layerConfigurationList =
                sortLayerConfigurations(
                        layerStack,
                        dtlsConfiguration,
                        messageConfiguration,
                        recordConfiguration,
                        ssl2Configuration,
                        quicFrameConfiguration,
                        quicPacketConfiguration,
                        httpConfiguration);
        LayerStackProcessingResult processingResult = layerStack.sendData(layerConfigurationList);
        setContainers(processingResult);
    }

    /**
     * Check if HTTP messages were set without an HTTP layer. This is a (temporary) safety check
     * since a distinct layer was not necessary for old TLS-Attacker versions.
     *
     * @param layerStack the active layer stack
     * @param givenHttpMessages preconfigured messages
     */
    private void checkLayerConsistency(LayerStack layerStack, List<HttpMessage> givenHttpMessages) {
        ImplementedLayers faultyLayer = null;
        if (!layerStack.getLayersInStack().contains(ImplementedLayers.HTTP)
                && givenHttpMessages != null
                && !givenHttpMessages.isEmpty()) {
            faultyLayer = ImplementedLayers.HTTP;
        }

        // TODO: extend for more layers?
        if (faultyLayer != null) {
            LOGGER.warn(
                    "Layer stack does not contain {} layer but {} messages were set. These messages will be ignored!",
                    faultyLayer,
                    faultyLayer);
        }
    }

    protected void receive(
            TlsContext tlsContext,
            List<ProtocolMessage> protocolMessagesToReceive,
            List<DtlsHandshakeMessageFragment> fragmentsToReceive,
            List<Record> recordsToReceive,
            List<QuicFrame> framesToReceive,
            List<QuicPacket> packetsToReceive,
            List<HttpMessage> httpMessagesToReceive) {
        LayerStack layerStack = tlsContext.getLayerStack();

        List<LayerConfiguration> layerConfigurationList;
        layerConfigurationList =
                sortLayerConfigurations(
                        layerStack,
                        getReceiveConfiguration(
                                ImplementedLayers.DTLS_FRAGMENT, fragmentsToReceive),
                        getReceiveConfiguration(
                                ImplementedLayers.MESSAGE, protocolMessagesToReceive),
                        getReceiveConfiguration(ImplementedLayers.SSL2, protocolMessagesToReceive),
                        getReceiveConfiguration(ImplementedLayers.RECORD, recordsToReceive),
                        getReceiveConfiguration(ImplementedLayers.HTTP, httpMessagesToReceive),
                        getReceiveConfiguration(ImplementedLayers.QUICFRAME, framesToReceive),
                        getReceiveConfiguration(ImplementedLayers.QUICPACKET, packetsToReceive));

        getReceiveResult(layerStack, layerConfigurationList);
    }

    protected void receiveQuic(
            TlsContext tlsContext,
            List<QuicFrame> framesToReceive,
            List<QuicPacket> packetsToReceive) {
        LayerStack layerStack = tlsContext.getLayerStack();

        List<LayerConfiguration> layerConfigurationList;

        layerConfigurationList =
                sortLayerConfigurations(
                        layerStack,
                        null,
                        null,
                        null,
                        null,
                        null,
                        getReceiveConfiguration(ImplementedLayers.QUICFRAME, framesToReceive),
                        getReceiveConfiguration(ImplementedLayers.QUICPACKET, packetsToReceive));

        getReceiveResult(layerStack, layerConfigurationList);
    }

    private ReceiveLayerConfiguration getReceiveConfiguration(
            LayerType layerType, List<? extends DataContainer<?>> containersToReceive) {
        if (containersToReceive == null || containersToReceive.isEmpty()) {
            return new GenericReceiveLayerConfiguration(layerType);
        } else {
            if (layerType == ImplementedLayers.MESSAGE) {
                return (ReceiveLayerConfiguration)
                        applyMessageFilters(
                                new SpecificReceiveLayerConfiguration<>(
                                        layerType, containersToReceive));
            }
            return new SpecificReceiveLayerConfiguration<>(layerType, containersToReceive);
        }
    }

    protected void receiveTill(TlsContext tlsContext, ProtocolMessage protocolMessageToReceive) {
        LayerStack layerStack = tlsContext.getLayerStack();

        LayerConfiguration messageConfiguration =
                new ReceiveTillLayerConfiguration(
                        ImplementedLayers.MESSAGE, protocolMessageToReceive);

        List<LayerConfiguration> layerConfigurationList =
                sortLayerConfigurations(layerStack, messageConfiguration);
        getReceiveResult(layerStack, layerConfigurationList);
    }

    protected void receiveTillQuic(
            TlsContext tlsContext,
            List<QuicFrame> framesToReceive,
            List<QuicPacket> packetsToReceive,
            int maxNumberOfQuicPacketsToReceive) {
        LayerStack layerStack = tlsContext.getLayerStack();

        List<LayerConfiguration> layerConfigurationList =
                sortLayerConfigurations(
                        layerStack,
                        null,
                        null,
                        null,
                        null,
                        null,
                        new ReceiveTillLayerConfiguration(
                                ImplementedLayers.QUICFRAME,
                                false,
                                maxNumberOfQuicPacketsToReceive,
                                framesToReceive),
                        new ReceiveTillLayerConfiguration(
                                ImplementedLayers.QUICPACKET,
                                false,
                                maxNumberOfQuicPacketsToReceive,
                                packetsToReceive));
        getReceiveResult(layerStack, layerConfigurationList);
    }

    protected void tightReceive(
            TlsContext tlsContext, List<ProtocolMessage> protocolMessagesToReceive) {
        LayerStack layerStack = tlsContext.getLayerStack();

        LayerConfiguration messageConfiguration =
                new TightReceiveLayerConfiguration(
                        ImplementedLayers.MESSAGE, protocolMessagesToReceive);

        List<LayerConfiguration> layerConfigurationList =
                sortLayerConfigurations(layerStack, messageConfiguration);
        getReceiveResult(layerStack, layerConfigurationList);
    }

    private void getReceiveResult(
            LayerStack layerStack, List<LayerConfiguration> layerConfigurationList) {
        LayerStackProcessingResult processingResult;
        processingResult = layerStack.receiveData(layerConfigurationList);
        setContainers(processingResult);
        setLayerStackProcessingResult(processingResult);
    }

    private void setContainers(LayerStackProcessingResult processingResults) {
        if (processingResults.getResultForLayer(ImplementedLayers.MESSAGE) != null) {
            messages =
                    new ArrayList<>(
                            processingResults
                                    .getResultForLayer(ImplementedLayers.MESSAGE)
                                    .getUsedContainers());
        }
        if (processingResults.getResultForLayer(ImplementedLayers.SSL2) != null) {
            messages =
                    new ArrayList<>(
                            processingResults
                                    .getResultForLayer(ImplementedLayers.SSL2)
                                    .getUsedContainers());
        }
        if (processingResults.getResultForLayer(ImplementedLayers.DTLS_FRAGMENT) != null) {
            fragments =
                    new ArrayList<>(
                            processingResults
                                    .getResultForLayer(ImplementedLayers.DTLS_FRAGMENT)
                                    .getUsedContainers());
        }
        if (processingResults.getResultForLayer(ImplementedLayers.RECORD) != null) {
            records =
                    new ArrayList<>(
                            processingResults
                                    .getResultForLayer(ImplementedLayers.RECORD)
                                    .getUsedContainers());
        }
        if (processingResults.getResultForLayer(ImplementedLayers.HTTP) != null) {
            httpMessages =
                    new ArrayList<>(
                            processingResults
                                    .getResultForLayer(ImplementedLayers.HTTP)
                                    .getUsedContainers());
        }
        if (processingResults.getResultForLayer(ImplementedLayers.QUICFRAME) != null) {
            quicFrames =
                    new ArrayList<>(
                            processingResults
                                    .getResultForLayer(ImplementedLayers.QUICFRAME)
                                    .getUsedContainers());
        }
        if (processingResults.getResultForLayer(ImplementedLayers.QUICPACKET) != null) {
            quicPackets =
                    new ArrayList<>(
                            processingResults
                                    .getResultForLayer(ImplementedLayers.QUICPACKET)
                                    .getUsedContainers());
        }
    }

    public LayerStackProcessingResult getLayerStackProcessingResult() {
        return layerStackProcessingResult;
    }

    public void setLayerStackProcessingResult(
            LayerStackProcessingResult layerStackProcessingResult) {
        this.layerStackProcessingResult = layerStackProcessingResult;
    }

    private LayerConfiguration applyMessageFilters(LayerConfiguration messageLayerConfiguration) {
        List<DataContainerFilter> containerFilters = new LinkedList<>();
        if (getActionOptions().contains(ActionOption.IGNORE_UNEXPECTED_APP_DATA)) {
            containerFilters.add(new GenericDataContainerFilter(ApplicationMessage.class));
        }
        if (getActionOptions().contains(ActionOption.IGNORE_UNEXPECTED_KEY_UPDATE_MESSAGES)) {
            containerFilters.add(new GenericDataContainerFilter(KeyUpdateMessage.class));
        }
        if (getActionOptions().contains(ActionOption.IGNORE_UNEXPECTED_NEW_SESSION_TICKETS)) {
            containerFilters.add(new GenericDataContainerFilter(NewSessionTicketMessage.class));
        }
        if (getActionOptions().contains(ActionOption.IGNORE_UNEXPECTED_WARNINGS)) {
            containerFilters.add(new WarningAlertFilter());
        }
        ((SpecificReceiveLayerConfiguration) messageLayerConfiguration)
                .setContainerFilterList(containerFilters);
        return messageLayerConfiguration;
    }

    public List<HttpMessage> getHttpMessages() {
        return httpMessages;
    }

    public void setHttpMessages(List<HttpMessage> httpMessages) {
        this.httpMessages = httpMessages;
    }

    public abstract MessageActionDirection getMessageDirection();

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }

        MessageAction that = (MessageAction) o;

        if (!Objects.equals(messages, that.messages)) {
            return false;
        }
        if (!Objects.equals(httpMessages, that.httpMessages)) {
            return false;
        }
        if (!Objects.equals(records, that.records)) {
            return false;
        }
        if (!Objects.equals(fragments, that.fragments)) {
            return false;
        }
        if (!Objects.equals(quicFrames, that.quicFrames)) {
            return false;
        }
        if (!Objects.equals(quicPackets, that.quicPackets)) {
            return false;
        }
        return Objects.equals(layerStackProcessingResult, that.layerStackProcessingResult);
    }

    @Override
    public int hashCode() {
        int result = super.hashCode();
        result = 31 * result + (messages != null ? messages.hashCode() : 0);
        result = 31 * result + (httpMessages != null ? httpMessages.hashCode() : 0);
        result = 31 * result + (records != null ? records.hashCode() : 0);
        result = 31 * result + (fragments != null ? fragments.hashCode() : 0);
        result = 31 * result + (quicFrames != null ? quicFrames.hashCode() : 0);
        result = 31 * result + (quicPackets != null ? quicPackets.hashCode() : 0);
        result =
                31 * result
                        + (layerStackProcessingResult != null
                                ? layerStackProcessingResult.hashCode()
                                : 0);
        return result;
    }
}
