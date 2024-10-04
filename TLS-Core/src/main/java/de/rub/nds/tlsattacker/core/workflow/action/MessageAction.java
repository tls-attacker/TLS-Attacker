/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.layer.LayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.LayerStack;
import de.rub.nds.tlsattacker.core.layer.LayerStackProcessingResult;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.IOException;
import java.util.List;
import java.util.Set;

@XmlRootElement(name = "MessageAction")
public abstract class MessageAction extends ConnectionBoundAction {

    @XmlElementWrapper
    @HoldsModifiableVariable
    @XmlElementRef
    protected List<ProtocolMessage> messages = new ArrayList<>();

    @XmlElementWrapper
    @HoldsModifiableVariable
    @XmlElements(value = { @XmlElement(type = HttpMessage.class, name = "HttpMessage") })
    protected List<HttpMessage> httpMessages = new ArrayList<>();

    @HoldsModifiableVariable
    @XmlElementWrapper
    @XmlElements(value = { @XmlElement(type = Record.class, name = "Record") })
    protected List<Record> records = new ArrayList<>();

    @HoldsModifiableVariable
    @XmlElementWrapper
    @XmlElements(value = { @XmlElement(type = DtlsHandshakeMessageFragment.class, name = "DtlsFragment") })
    protected List<DtlsHandshakeMessageFragment> fragments = new ArrayList<>();

    @XmlTransient
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

    public MessageAction(Set<ActionOption> actionOptions, String connectionAlias) {
        super(actionOptions, connectionAlias);
    }

    public MessageAction(Set<ActionOption> actionOptions) {
        super(actionOptions);
    }

    public boolean isSendingAction() {
        return this instanceof SendingAction;
    }

    public boolean isReceivingAction() {
        return this instanceof ReceivingAction;
    }

    protected LayerStackProcessingResult getReceiveResult(
            LayerStack layerStack, List<LayerConfiguration<?>> layerConfigurationList) {
        layerStackProcessingResult = layerStack.receiveData(layerConfigurationList);
        return layerStackProcessingResult;
    }

    protected LayerStackProcessingResult getSendResult(
            LayerStack layerStack, List<LayerConfiguration<?>> layerConfigurationList)
            throws IOException {
        LayerStack layerStack = tlsContext.getLayerStack();

        LayerConfiguration dtlsConfiguration = new SpecificSendLayerConfiguration<>(
                ImplementedLayers.DTLS_FRAGMENT, fragmentsToSend);
        LayerConfiguration messageConfiguration = new SpecificSendLayerConfiguration<>(
                ImplementedLayers.MESSAGE, protocolMessagesToSend);
        LayerConfiguration ssl2Configuration = new SpecificSendLayerConfiguration(ImplementedLayers.SSL2,
                protocolMessagesToSend);
        LayerConfiguration recordConfiguration = new SpecificSendLayerConfiguration<>(ImplementedLayers.RECORD,
                recordsToSend);
        LayerConfiguration httpConfiguration = new SpecificSendLayerConfiguration<>(ImplementedLayers.HTTP,
                httpMessagesToSend);

        checkLayerConsistency(layerStack, httpMessagesToSend);

        List<LayerConfiguration> layerConfigurationList = sortLayerConfigurations(
                layerStack,
                dtlsConfiguration,
                messageConfiguration,
                recordConfiguration,
                ssl2Configuration,
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
            List<HttpMessage> httpMessagesToReceive) {
        LayerStack layerStack = tlsContext.getLayerStack();

        List<LayerConfiguration> layerConfigurationList;
        if (protocolMessagesToReceive == null
                && fragmentsToReceive == null
                && recordsToReceive == null
                && httpMessagesToReceive == null) {
            layerConfigurationList = getGenericReceiveConfigurations(layerStack);
        } else {
            layerConfigurationList = getSpecificReceiveConfigurations(
                    fragmentsToReceive,
                    protocolMessagesToReceive,
                    recordsToReceive,
                    httpMessagesToReceive,
                    layerStack);
        }

        getReceiveResult(layerStack, layerConfigurationList);
    }

    private List<LayerConfiguration> getGenericReceiveConfigurations(LayerStack layerStack) {
        List<LayerConfiguration> layerConfigurationList;
        LayerConfiguration dtlsConfiguration = new GenericReceiveLayerConfiguration(ImplementedLayers.DTLS_FRAGMENT);
        LayerConfiguration messageConfiguration = new GenericReceiveLayerConfiguration(ImplementedLayers.MESSAGE);
        LayerConfiguration ssl2Configuration = new GenericReceiveLayerConfiguration(ImplementedLayers.HTTP);
        LayerConfiguration recordConfiguration = new GenericReceiveLayerConfiguration(ImplementedLayers.RECORD);
        LayerConfiguration httpConfiguration = new GenericReceiveLayerConfiguration(ImplementedLayers.HTTP);
        layerConfigurationList = sortLayerConfigurations(
                layerStack,
                dtlsConfiguration,
                messageConfiguration,
                recordConfiguration,
                ssl2Configuration,
                httpConfiguration);
        return layerConfigurationList;
    }

    private List<LayerConfiguration> getSpecificReceiveConfigurations(
            List<DtlsHandshakeMessageFragment> fragmentsToReceive,
            List<ProtocolMessage> protocolMessagesToReceive,
            List<Record> recordsToReceive,
            List<HttpMessage> httpMessagesToReceive,
            LayerStack layerStack) {
        List<LayerConfiguration> layerConfigurationList;
        LayerConfiguration dtlsConfiguration = new SpecificReceiveLayerConfiguration(
                ImplementedLayers.DTLS_FRAGMENT, fragmentsToReceive);
        LayerConfiguration messageConfiguration = new SpecificReceiveLayerConfiguration<>(
                ImplementedLayers.MESSAGE, protocolMessagesToReceive);
        LayerConfiguration ssl2Configuration = new SpecificReceiveLayerConfiguration<>(
                ImplementedLayers.SSL2, protocolMessagesToReceive);
        LayerConfiguration recordConfiguration = new SpecificReceiveLayerConfiguration<>(ImplementedLayers.RECORD,
                recordsToReceive);
        if (recordsToReceive == null || recordsToReceive.isEmpty()) {
            // always allow (trailing) records when no records were set
            // a ReceiveAction actually intended to expect no records is pointless
            ((SpecificReceiveLayerConfiguration) recordConfiguration)
                    .setAllowTrailingContainers(true);
        }
        LayerConfiguration httpConfiguration = new SpecificReceiveLayerConfiguration<>(
                ImplementedLayers.HTTP, httpMessagesToReceive);
        applyActionOptionFilters(messageConfiguration);
        layerConfigurationList = sortLayerConfigurations(
                layerStack,
                dtlsConfiguration,
                messageConfiguration,
                recordConfiguration,
                ssl2Configuration,
                httpConfiguration);
        return layerConfigurationList;
    }

    protected void receiveTill(TlsContext tlsContext, ProtocolMessage protocolMessageToReceive) {
        LayerStack layerStack = tlsContext.getLayerStack();

        LayerConfiguration messageConfiguration = new ReceiveTillLayerConfiguration(
                ImplementedLayers.MESSAGE, protocolMessageToReceive);

        List<LayerConfiguration> layerConfigurationList = sortLayerConfigurations(layerStack, messageConfiguration);
        getReceiveResult(layerStack, layerConfigurationList);
    }

    protected void tightReceive(
            TlsContext tlsContext, List<ProtocolMessage> protocolMessagesToReceive) {
        LayerStack layerStack = tlsContext.getLayerStack();

        LayerConfiguration messageConfiguration = new TightReceiveLayerConfiguration(
                ImplementedLayers.MESSAGE, protocolMessagesToReceive);

        List<LayerConfiguration> layerConfigurationList = sortLayerConfigurations(layerStack, messageConfiguration);
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
            messages = new ArrayList<>(
                    processingResults
                            .getResultForLayer(ImplementedLayers.MESSAGE)
                            .getUsedContainers());
        }
        if (processingResults.getResultForLayer(ImplementedLayers.SSL2) != null) {
            messages = new ArrayList<>(
                    processingResults
                            .getResultForLayer(ImplementedLayers.SSL2)
                            .getUsedContainers());
        }
        if (processingResults.getResultForLayer(ImplementedLayers.DTLS_FRAGMENT) != null) {
            fragments = new ArrayList<>(
                    processingResults
                            .getResultForLayer(ImplementedLayers.DTLS_FRAGMENT)
                            .getUsedContainers());
        }
        if (processingResults.getResultForLayer(ImplementedLayers.RECORD) != null) {
            records = new ArrayList<>(
                    processingResults
                            .getResultForLayer(ImplementedLayers.RECORD)
                            .getUsedContainers());
        }
        if (processingResults.getResultForLayer(ImplementedLayers.HTTP) != null) {
            httpMessages = new ArrayList<>(
                    processingResults
                            .getResultForLayer(ImplementedLayers.HTTP)
                            .getUsedContainers());
        }
    }

    public LayerStackProcessingResult getLayerStackProcessingResult() {
        return layerStackProcessingResult;
    }

    public abstract MessageActionDirection getMessageDirection();

    @Override
    public void reset() {
        layerStackProcessingResult = null;
        setExecuted(null);
    }

    void setLayerStackProcessingResult(LayerStackProcessingResult layerStackProcessingResult) {
        this.layerStackProcessingResult = layerStackProcessingResult;
    }
}
