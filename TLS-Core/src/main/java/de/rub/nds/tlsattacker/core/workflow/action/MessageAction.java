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
import de.rub.nds.tlsattacker.core.layer.*;
import de.rub.nds.tlsattacker.core.layer.constant.ImplementedLayers;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlElementRef;
import javax.xml.bind.annotation.XmlElementWrapper;
import javax.xml.bind.annotation.XmlElements;

public abstract class MessageAction<MessageType extends Message> extends ConnectionBoundAction {

    @XmlElementWrapper
    @HoldsModifiableVariable
    @XmlElementRef
    protected List<MessageType> messages = new ArrayList<>();

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

    public MessageAction(List<MessageType> messages) {
        this.messages = new ArrayList<>(messages);
    }

    public MessageAction(MessageType... messages) {
        this.messages = new ArrayList<>(Arrays.asList(messages));
    }

    public MessageAction(String connectionAlias) {
        super(connectionAlias);
    }

    public MessageAction(String connectionAlias, List<MessageType> messages) {
        super(connectionAlias);
        this.messages = new ArrayList<>(messages);
    }

    public MessageAction(String connectionAlias, MessageType... messages) {
        this(connectionAlias, new ArrayList<>(Arrays.asList(messages)));
    }

    public String getReadableString(MessageType... messages) {
        return getReadableString(Arrays.asList(messages));
    }

    public String getReadableString(List<MessageType> messages) {
        return getReadableString(messages, false);
    }

    public String getReadableString(List<MessageType> messages, Boolean verbose) {
        StringBuilder builder = new StringBuilder();
        if (messages == null) {
            return builder.toString();
        }
        for (MessageType message : messages) {
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

    public List<MessageType> getMessages() {
        return messages;
    }

    public void setMessages(List<MessageType> messages) {
        this.messages = messages;
    }

    public void setMessages(MessageType... messages) {
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

    public abstract MessageActionDirection getMessageDirection();

    protected void send(TlsContext tlsContext, List<MessageType> messagesToSend, List<Record> recordsToSend)
        throws IOException {
        LayerStack layerStack = tlsContext.getLayerStack();
        List<LayerConfiguration> layerConfigurationList = new LinkedList<>();
        LayerConfiguration messageLayerConfig = new SpecificSendLayerConfiguration(messagesToSend);
        layerConfigurationList.add(messageLayerConfig);
        layerConfigurationList.add(new SpecificSendLayerConfiguration(recordsToSend));
        layerConfigurationList.add(new SpecificSendLayerConfiguration((List) null));
        LayerStackProcessingResult processingResult = layerStack.sendData(layerConfigurationList);
        setContainers(processingResult);
    }

    protected void receive(TlsContext tlsContext, List<MessageType> protocolMessagesToReceive,
        List<Record> recordsToReceive) {
        LayerStack layerStack = tlsContext.getLayerStack();
        List<LayerConfiguration> layerConfigurationList = new LinkedList<>();
        LayerConfiguration messageLayerConfig = new SpecificReceiveLayerConfiguration(protocolMessagesToReceive);
        layerConfigurationList.add(messageLayerConfig);
        layerConfigurationList.add(new SpecificReceiveLayerConfiguration(recordsToReceive));
        layerConfigurationList.add(null);
        getReceiveResult(layerStack, layerConfigurationList);
    }

    protected void receiveTill(TlsContext tlsContext, MessageType protocolMessageToReceive) {
        LayerStack layerStack = tlsContext.getLayerStack();
        List<LayerConfiguration> layerConfigurationList = new LinkedList<>();
        layerConfigurationList.add(new ReceiveTillLayerConfiguration(protocolMessageToReceive));
        layerConfigurationList.add(null);
        layerConfigurationList.add(null);
        getReceiveResult(layerStack, layerConfigurationList);
    }

    protected void tightReceive(TlsContext tlsContext, List<MessageType> protocolMessagesToReceive) {
        LayerStack layerStack = tlsContext.getLayerStack();
        List<LayerConfiguration> layerConfigurationList = new LinkedList<>();
        layerConfigurationList.add(new TightReceiveLayerConfiguration(protocolMessagesToReceive));
        layerConfigurationList.add(null);
        layerConfigurationList.add(null);
        getReceiveResult(layerStack, layerConfigurationList);
    }

    private void getReceiveResult(LayerStack layerStack, List<LayerConfiguration> layerConfigurationList) {
        LayerStackProcessingResult processingResult;
        try {
            processingResult = layerStack.receiveData(layerConfigurationList);
            setContainers(processingResult);
            setLayerStackProcessingResult(processingResult);
        } catch (IOException ex) {
            LOGGER.warn("Received an IOException", ex);
            LayerStackProcessingResult reconstructedResult = layerStack.gatherResults();
            setContainers(reconstructedResult);
            setLayerStackProcessingResult(reconstructedResult);
        }
    }

    private void setContainers(LayerStackProcessingResult processingResults) {
        messages = new ArrayList<>(processingResults.getResultForLayer(ImplementedLayers.MESSAGE).getUsedContainers());
        records = new ArrayList<>(processingResults.getResultForLayer(ImplementedLayers.RECORD).getUsedContainers());
    }

    public enum MessageActionDirection {
        SENDING,
        RECEIVING
    }

    public LayerStackProcessingResult getLayerStackProcessingResult() {
        return layerStackProcessingResult;
    }

    public void setLayerStackProcessingResult(LayerStackProcessingResult layerStackProcessingResult) {
        this.layerStackProcessingResult = layerStackProcessingResult;
    }

}
