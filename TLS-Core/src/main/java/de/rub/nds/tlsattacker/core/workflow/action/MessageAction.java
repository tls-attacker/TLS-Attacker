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
