/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.http.HttpMessage;
import de.rub.nds.tlsattacker.core.layer.DataContainerFilter;
import de.rub.nds.tlsattacker.core.layer.GenericReceiveLayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.LayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.LayerProcessingResult;
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
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.IOException;
import java.util.LinkedList;
import java.util.List;
import java.util.StringJoiner;

@XmlRootElement(name = "MessageAction")
public abstract class MessageAction extends ConnectionBoundAction {

    public enum MessageActionDirection {
        SENDING,
        RECEIVING
    }

    @XmlElement(name = "result")
    private LayerStackProcessingResult layerStackProcessingResult;

    public MessageAction() {}

    public MessageAction(String connectionAlias) {
        super(connectionAlias);
    }

    protected String getReadableStringFromConfiguration(List<LayerConfiguration> configurations) {
        StringBuilder sb = new StringBuilder();
        for (LayerConfiguration configuration : configurations) {
            sb.append(configuration.toCompactString());
            sb.append(System.lineSeparator());
        }
        sb.trimToSize();
        return sb.toString();
    }

    protected String getReadableStringFromDataContainers(List<DataContainer<?>> containerList) {
        StringBuilder sb = new StringBuilder();
        StringJoiner joiner = new StringJoiner(", ");
        for (DataContainer container : containerList) {
            joiner.add(container.toCompactString());
        }
        sb.trimToSize();
        return sb.toString();
    }

    protected String getReadableString(LayerStackProcessingResult processingResult) {
        StringBuilder sb = new StringBuilder();
        for (LayerProcessingResult result : processingResult.getLayerProcessingResultList()) {
            sb.append(result.toCompactString());
            sb.append(System.lineSeparator());
        }
        sb.trimToSize();
        return sb.toString();
    }

    public boolean isSendingAction() {
        return this instanceof SendingAction;
    }

    public boolean isReceivingAction() {
        return this instanceof ReceivingAction;
    }

    protected List<LayerConfiguration> createSendConfiguration(
            TlsContext tlsContext,
            List<ProtocolMessage> protocolMessagesToSend,
            List<DtlsHandshakeMessageFragment> fragmentsToSend,
            List<Record> recordsToSend,
            List<QuicFrame> framesToSend,
            List<QuicPacket> packetsToSend,
            List<HttpMessage> httpMessagesToSend) {
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
        return layerConfigurationList;
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

    protected List<LayerConfiguration> createReceivLayerConfiguration(
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
                        createReceiveConfiguration(
                                ImplementedLayers.DTLS_FRAGMENT, fragmentsToReceive),
                        createReceiveConfiguration(
                                ImplementedLayers.MESSAGE, protocolMessagesToReceive),
                        createReceiveConfiguration(
                                ImplementedLayers.SSL2, protocolMessagesToReceive),
                        createReceiveConfiguration(ImplementedLayers.RECORD, recordsToReceive),
                        createReceiveConfiguration(ImplementedLayers.HTTP, httpMessagesToReceive),
                        createReceiveConfiguration(ImplementedLayers.QUICFRAME, framesToReceive),
                        createReceiveConfiguration(ImplementedLayers.QUICPACKET, packetsToReceive));
        return layerConfigurationList;
    }

    private ReceiveLayerConfiguration createReceiveConfiguration(
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

    protected List<LayerConfiguration> createReceiveTillConfiguration(
            TlsContext tlsContext, List<QuicFrame> quicFrame, List<QuicPacket> quicPacket) {
        LayerStack layerStack = tlsContext.getLayerStack();

        LayerConfiguration messageConfiguration =
                new ReceiveTillLayerConfiguration(ImplementedLayers.QUICFRAME, quicFrame);

        return sortLayerConfigurations(layerStack, messageConfiguration);
    }

    protected List<LayerConfiguration> createReceiveTillConfiguration(
            TlsContext tlsContext, ProtocolMessage protocolMessageToReceive) {
        LayerStack layerStack = tlsContext.getLayerStack();

        LayerConfiguration messageConfiguration =
                new ReceiveTillLayerConfiguration(
                        ImplementedLayers.MESSAGE, protocolMessageToReceive);

        return sortLayerConfigurations(layerStack, messageConfiguration);
    }

    protected List<LayerConfiguration> createTightReceiveConfiguration(
            TlsContext tlsContext, List<ProtocolMessage> protocolMessagesToReceive) {
        LayerStack layerStack = tlsContext.getLayerStack();

        LayerConfiguration messageConfiguration =
                new TightReceiveLayerConfiguration(
                        ImplementedLayers.MESSAGE, protocolMessagesToReceive);

        List<LayerConfiguration> layerConfigurationList =
                sortLayerConfigurations(layerStack, messageConfiguration);
        return layerConfigurationList;
    }

    protected LayerStackProcessingResult getReceiveResult(
            LayerStack layerStack, List<LayerConfiguration> layerConfigurationList) {
        layerStackProcessingResult = layerStack.receiveData(layerConfigurationList);
        return layerStackProcessingResult;
    }

    protected LayerStackProcessingResult getSendResult(
            LayerStack layerStack, List<LayerConfiguration> layerConfigurationList)
            throws IOException {
        layerStackProcessingResult = layerStack.sendData(layerConfigurationList);
        return layerStackProcessingResult;
    }

    public LayerStackProcessingResult getLayerStackProcessingResult() {
        return layerStackProcessingResult;
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

    public abstract MessageActionDirection getMessageDirection();

    @Override
    public void reset() {
        layerStackProcessingResult = null;
        setExecuted(null);
    }

    public List<DataContainer<?>> getDataContainersForLayer(LayerType type) {
        if (getLayerStackProcessingResult() == null) {
            return null;
        } else {
            for (LayerProcessingResult<?> result :
                    getLayerStackProcessingResult().getLayerProcessingResultList()) {
                if (result.getLayerType() == type) {
                    return (List<DataContainer<?>>) result.getUsedContainers();
                }
            }
            return new LinkedList<>();
        }
    }

    void setLayerStackProcessingResult(LayerStackProcessingResult layerStackProcessingResult) {
        this.layerStackProcessingResult = layerStackProcessingResult;
    }
}
