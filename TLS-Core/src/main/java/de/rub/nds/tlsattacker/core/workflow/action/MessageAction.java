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
import de.rub.nds.tlsattacker.core.constants.MessageActionDirection;
import de.rub.nds.tlsattacker.core.layer.LayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.LayerStack;
import de.rub.nds.tlsattacker.core.layer.LayerStackProcessingResult;
import de.rub.nds.tlsattacker.core.layer.SpecificContainerLayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.constant.ImplementedLayers;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlElementRef;
import javax.xml.bind.annotation.XmlElementWrapper;
import javax.xml.bind.annotation.XmlElements;

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

    public abstract MessageActionDirection getMessageDirection();

    protected void send(TlsContext tlsContext, List<ProtocolMessage> protocolMessagesToSend,
        List<DtlsHandshakeMessageFragment> fragmentsToSend, List<Record> recordsToSend) throws IOException {
        LayerStack layerStack = tlsContext.getLayerStack();
        List<LayerConfiguration> layerConfigurationList = new LinkedList<>();
        layerConfigurationList.add(new SpecificContainerLayerConfiguration(protocolMessagesToSend));
        if (tlsContext.getChooser().getSelectedProtocolVersion().isDTLS()) {
            layerConfigurationList.add(new SpecificContainerLayerConfiguration(fragmentsToSend));
        }
        layerConfigurationList.add(new SpecificContainerLayerConfiguration(recordsToSend));
        layerConfigurationList.add(new SpecificContainerLayerConfiguration((List) null));
        LayerStackProcessingResult processingResult = layerStack.sendData(layerConfigurationList);
        setContainers(processingResult);
    }

    protected void receive(TlsContext tlsContext, List<ProtocolMessage> protocolMessagesToReceive,
        List<DtlsHandshakeMessageFragment> fragmentsToReceive, List<Record> recordsToReceive) {
        LayerStack layerStack = tlsContext.getLayerStack();
        List<LayerConfiguration> layerConfigurationList = new LinkedList<>();
        layerConfigurationList.add(new SpecificContainerLayerConfiguration(protocolMessagesToReceive));
        if (tlsContext.getChooser().getSelectedProtocolVersion().isDTLS()) {
            layerConfigurationList.add(new SpecificContainerLayerConfiguration(fragmentsToReceive));
        }
        layerConfigurationList.add(new SpecificContainerLayerConfiguration(recordsToReceive));
        layerConfigurationList.add(new SpecificContainerLayerConfiguration((List) null));
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
        // TODO add fragments?
        // fragments = new
        // ArrayList<>(processingResults.getResultForLayer(ImplementedLayers.DTLS_FRAGMENT).getUsedContainers());
        records = new ArrayList<>(processingResults.getResultForLayer(ImplementedLayers.RECORD).getUsedContainers());
    }

    protected void receiveTill(TlsContext tlsContext, List<ProtocolMessage> protocolMessagesToSend,
        List<Record> recordsToSend) {
        LayerStack layerStack = tlsContext.getLayerStack();
        List<LayerConfiguration> layerConfigurationList = new LinkedList<>();
        layerConfigurationList.add(new SpecificContainerLayerConfiguration(protocolMessagesToSend));
        layerConfigurationList.add(new SpecificContainerLayerConfiguration(recordsToSend));
        layerConfigurationList.add(new SpecificContainerLayerConfiguration((List) null));
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

    public LayerStackProcessingResult getLayerStackProcessingResult() {
        return layerStackProcessingResult;
    }

    public void setLayerStackProcessingResult(LayerStackProcessingResult layerStackProcessingResult) {
        this.layerStackProcessingResult = layerStackProcessingResult;
    }

}
