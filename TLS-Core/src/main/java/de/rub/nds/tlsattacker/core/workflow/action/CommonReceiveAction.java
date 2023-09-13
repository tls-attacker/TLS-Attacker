/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.http.HttpMessage;
import de.rub.nds.tlsattacker.core.layer.LayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.LayerProcessingResult;
import de.rub.nds.tlsattacker.core.layer.constant.ImplementedLayers;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.state.State;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

public abstract class CommonReceiveAction extends MessageAction implements ReceivingAction {

    public CommonReceiveAction() {
        super();
    }

    public CommonReceiveAction(List<ProtocolMessage<?>> messages) {
        super(messages);
    }

    public CommonReceiveAction(ProtocolMessage<?>... messages) {
        super(messages);
    }

    public CommonReceiveAction(String connectionAlias) {
        super(connectionAlias);
    }

    public CommonReceiveAction(String connectionAlias, List<ProtocolMessage<?>> messages) {
        super(connectionAlias, messages);
    }

    public CommonReceiveAction(String connectionAlias, ProtocolMessage<?>... messages) {
        super(connectionAlias, messages);
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        TlsContext tlsContext = state.getTlsContext(getConnectionAlias());

        if (isExecuted()) {
            throw new ActionExecutionException("Action already executed!");
        }

        LOGGER.debug("Receiving Messages...");
        receive(tlsContext, createConfigurationList());

        setExecuted(true);

        String expected = getReadableString(getExpectedMessages());
        LOGGER.debug("Receive Expected:" + expected);
        String received = getReadableString(messages);
        if (hasDefaultAlias()) {
            LOGGER.info("Received Messages: " + received);
        } else {
            LOGGER.info("Received Messages (" + getConnectionAlias() + "): " + received);
        }
    }

    @Override
    public boolean executedAsPlanned() {
        if (getLayerStackProcessingResult() != null) {
            for (LayerProcessingResult<?> result :
                    getLayerStackProcessingResult().getLayerProcessingResultList()) {
                if (!result.isExecutedAsPlanned()) {
                    return false;
                }
            }
            return true;
        }
        return false;
    }

    void setReceivedMessages(List<ProtocolMessage<?>> receivedMessages) {
        this.messages = receivedMessages;
    }

    void setReceivedRecords(List<Record> receivedRecords) {
        this.records = receivedRecords;
    }

    void setReceivedFragments(List<DtlsHandshakeMessageFragment> fragments) {
        this.fragments = fragments;
    }

    @Override
    public void reset() {
        messages = null;
        records = null;
        fragments = null;
        setExecuted(false);
    }

    @Override
    public List<ProtocolMessage<?>> getReceivedMessages() {
        return messages;
    }

    @Override
    public List<Record> getReceivedRecords() {
        return records;
    }

    @Override
    public List<DtlsHandshakeMessageFragment> getReceivedFragments() {
        return fragments;
    }

    @Override
    public List<HttpMessage<?>> getReceivedHttpMessages() {
        return httpMessages;
    }

    public final List<ProtocolMessage<?>> getExpectedMessages() {
        List<LayerConfiguration<?>> configurations = createConfigurationList();
        for (LayerConfiguration<?> configuration : configurations) {
            if (configuration.getLayerType() == ImplementedLayers.MESSAGE) {
                return configuration.getContainerList().stream()
                        .filter(container -> container instanceof ProtocolMessage<?>)
                        .map(container -> (ProtocolMessage<?>) container)
                        .collect(Collectors.toList());
            }
        }
        return null;
    }

    protected abstract List<LayerConfiguration<?>> createConfigurationList();

    public List<ProtocolMessageType> getGoingToReceiveProtocolMessageTypes() {
        List<LayerConfiguration<?>> configurations = createConfigurationList();
        for (LayerConfiguration<?> configuration : configurations) {
            if (configuration.getLayerType() == ImplementedLayers.MESSAGE) {
                List<ProtocolMessageType> protocolMessageTypes = new ArrayList<>();
                for (Object container : configuration.getContainerList()) {
                    if (container instanceof ProtocolMessage<?>) {
                        protocolMessageTypes.add(
                                ((ProtocolMessage<?>) container).getProtocolMessageType());
                    }
                }
                return protocolMessageTypes;
            }
        }
        return null;
    }

    public List<HandshakeMessageType> getGoingToReceiveHandshakeMessageTypes() {
        List<LayerConfiguration<?>> configurations = createConfigurationList();
        for (LayerConfiguration<?> configuration : configurations) {
            if (configuration.getLayerType() == ImplementedLayers.MESSAGE) {
                List<HandshakeMessageType> handshakeMessageTypes = new ArrayList<>();
                for (Object container : configuration.getContainerList()) {
                    if (container instanceof ProtocolMessage<?>) {
                        handshakeMessageTypes.add(
                                ((HandshakeMessage<?>) container).getHandshakeMessageType());
                    }
                }
                return handshakeMessageTypes;
            }
        }
        return null;
    }
}
