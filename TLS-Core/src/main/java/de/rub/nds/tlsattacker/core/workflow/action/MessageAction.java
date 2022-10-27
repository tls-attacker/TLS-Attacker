/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.layer.*;
import de.rub.nds.tlsattacker.core.layer.constant.ImplementedLayers;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlElementWrapper;
import jakarta.xml.bind.annotation.XmlElements;

import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.record.Record;
import jakarta.xml.bind.annotation.XmlElementRef;

public abstract class MessageAction extends ConnectionBoundAction {

    @XmlElementWrapper
    @HoldsModifiableVariable
    @XmlElementRef
    protected List<ProtocolMessage> messages = new ArrayList<>();

    @HoldsModifiableVariable
    @XmlElementWrapper
    @XmlElements(value = { @XmlElement(type = Record.class, name = "Record") })
    protected List<Record> records = new ArrayList<>();

    @HoldsModifiableVariable
    @XmlElementWrapper
    @XmlElements(value = { @XmlElement(type = DtlsHandshakeMessageFragment.class, name = "DtlsFragment") })
    protected List<DtlsHandshakeMessageFragment> fragments = new ArrayList<>();

    private LayerStackProcessingResult layerStackProcessingResult;

    public MessageAction() {
    }

    public MessageAction(List<ProtocolMessage> messages) {
        this.messages = new ArrayList<>(messages);
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

    public String getReadableString(ProtocolMessage... messages) {
        return getReadableString(Arrays.asList(messages));
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
    }

    public boolean isSendingAction() {
        return this instanceof SendingAction;
    }

    public boolean isReceivingAction() {
        return this instanceof ReceivingAction;
    }

    protected void send(TlsContext tlsContext, List<ProtocolMessage> protocolMessagesToSend,
        List<DtlsHandshakeMessageFragment> fragmentsToSend, List<Record> recordsToSend) throws IOException {
        LayerStack layerStack = tlsContext.getLayerStack();

        LayerConfiguration dtlsConfiguration =
            new SpecificSendLayerConfiguration<>(ImplementedLayers.DTLS_FRAGMENT, fragmentsToSend);
        LayerConfiguration messageConfiguration =
            new SpecificSendLayerConfiguration<>(ImplementedLayers.MESSAGE, protocolMessagesToSend);
        LayerConfiguration recordConfiguration =
            new SpecificSendLayerConfiguration<>(ImplementedLayers.RECORD, recordsToSend);

        List<LayerConfiguration> layerConfigurationList =
            sortLayerConfigurations(layerStack, dtlsConfiguration, messageConfiguration, recordConfiguration);
        LayerStackProcessingResult processingResult = layerStack.sendData(layerConfigurationList);
        setContainers(processingResult);
    }

    protected void receive(TlsContext tlsContext, List<ProtocolMessage> protocolMessagesToReceive,
        List<DtlsHandshakeMessageFragment> fragmentsToReceive, List<Record> recordsToReceive) {
        LayerStack layerStack = tlsContext.getLayerStack();

        LayerConfiguration dtlsConfiguration =
            new SpecificReceiveLayerConfiguration(ImplementedLayers.DTLS_FRAGMENT, fragmentsToReceive);
        LayerConfiguration messageConfiguration =
            new SpecificReceiveLayerConfiguration<>(ImplementedLayers.MESSAGE, protocolMessagesToReceive);
        LayerConfiguration recordConfiguration =
            new SpecificReceiveLayerConfiguration<>(ImplementedLayers.RECORD, recordsToReceive);

        List<LayerConfiguration> layerConfigurationList =
            sortLayerConfigurations(layerStack, dtlsConfiguration, messageConfiguration, recordConfiguration);
        getReceiveResult(layerStack, layerConfigurationList);
    }

    protected void receiveTill(TlsContext tlsContext, ProtocolMessage protocolMessageToReceive) {
        LayerStack layerStack = tlsContext.getLayerStack();

        LayerConfiguration messageConfiguration =
            new ReceiveTillLayerConfiguration(ImplementedLayers.MESSAGE, protocolMessageToReceive);

        List<LayerConfiguration> layerConfigurationList = sortLayerConfigurations(layerStack, messageConfiguration);
        getReceiveResult(layerStack, layerConfigurationList);
    }

    protected void tightReceive(TlsContext tlsContext, List<ProtocolMessage> protocolMessagesToReceive) {
        LayerStack layerStack = tlsContext.getLayerStack();

        LayerConfiguration messageConfiguration =
            new TightReceiveLayerConfiguration(ImplementedLayers.MESSAGE, protocolMessagesToReceive);

        List<LayerConfiguration> layerConfigurationList = sortLayerConfigurations(layerStack, messageConfiguration);
        getReceiveResult(layerStack, layerConfigurationList);
    }

    private void getReceiveResult(LayerStack layerStack, List<LayerConfiguration> layerConfigurationList) {
        LayerStackProcessingResult processingResult;
        processingResult = layerStack.receiveData(layerConfigurationList);
        setContainers(processingResult);
        setLayerStackProcessingResult(processingResult);
    }

    private void setContainers(LayerStackProcessingResult processingResults) {
        if (processingResults.getResultForLayer(ImplementedLayers.MESSAGE) != null) {
            messages =
                new ArrayList<>(processingResults.getResultForLayer(ImplementedLayers.MESSAGE).getUsedContainers());
        }
        if (processingResults.getResultForLayer(ImplementedLayers.DTLS_FRAGMENT) != null) {
            fragments = new ArrayList<>(
                processingResults.getResultForLayer(ImplementedLayers.DTLS_FRAGMENT).getUsedContainers());
        }
        if (processingResults.getResultForLayer(ImplementedLayers.RECORD) != null) {
            records =
                new ArrayList<>(processingResults.getResultForLayer(ImplementedLayers.RECORD).getUsedContainers());
        }
    }

    public LayerStackProcessingResult getLayerStackProcessingResult() {
        return layerStackProcessingResult;
    }

    public void setLayerStackProcessingResult(LayerStackProcessingResult layerStackProcessingResult) {
        this.layerStackProcessingResult = layerStackProcessingResult;
    }

}
