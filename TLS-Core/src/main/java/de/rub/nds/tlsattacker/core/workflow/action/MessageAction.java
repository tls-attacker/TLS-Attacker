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
import de.rub.nds.tlsattacker.core.layer.LayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.LayerProcessingResult;
import de.rub.nds.tlsattacker.core.layer.LayerStack;
import de.rub.nds.tlsattacker.core.layer.LayerStackProcessingResult;
import de.rub.nds.tlsattacker.core.layer.SpecificReceiveLayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.constant.ImplementedLayers;
import de.rub.nds.tlsattacker.core.layer.data.DataContainer;
import de.rub.nds.tlsattacker.core.layer.impl.DataContainerFilters.GenericDataContainerFilter;
import de.rub.nds.tlsattacker.core.layer.impl.DataContainerFilters.Tls.WarningAlertFilter;
import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.core.protocol.message.KeyUpdateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.NewSessionTicketMessage;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.IOException;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
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

    public MessageAction(Set<ActionOption> actionOptions, String connectionAlias) {
        super(actionOptions, connectionAlias);
    }

    public MessageAction(Set<ActionOption> actionOptions) {
        super(actionOptions);
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

    protected String getReadableStringFromDataContainers(
            List<DataContainer<?>>... containerListArray) {
        StringBuilder sb = new StringBuilder();
        StringJoiner joiner = new StringJoiner(", ");
        for (List<DataContainer<?>> containerList : containerListArray) {
            if (containerList != null) {
                for (DataContainer<?> container : containerList) {
                    joiner.add(container.toCompactString());
                }
            }
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
