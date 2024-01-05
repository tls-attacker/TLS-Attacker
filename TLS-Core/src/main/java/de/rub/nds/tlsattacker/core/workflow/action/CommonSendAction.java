/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.layer.LayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.LayerStackProcessingResult;
import de.rub.nds.tlsattacker.core.layer.constant.ImplementedLayers;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.printer.LogPrinter;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import de.rub.nds.tlsattacker.core.quic.frame.QuicFrame;
import de.rub.nds.tlsattacker.core.quic.packet.QuicPacket;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import de.rub.nds.tlsattacker.core.workflow.container.ActionHelperUtil;
import java.io.IOException;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

public abstract class CommonSendAction extends MessageAction implements SendingAction {

    public CommonSendAction() {
        super();
    }

    public CommonSendAction(String connectionAlias) {
        super(connectionAlias);
    }

    public CommonSendAction(Set<ActionOption> actionOptions, String connectionAlias) {
        super(actionOptions, connectionAlias);
    }

    @Override
    public final Set<String> getAllSendingAliases() {
        return new HashSet<>(Collections.singleton(connectionAlias));
    }

    @Override
    public final MessageActionDirection getMessageDirection() {
        return MessageActionDirection.SENDING;
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        TlsContext tlsContext = state.getContext(connectionAlias).getTlsContext();

        if (isExecuted()) {
            throw new ActionExecutionException("Action already executed!");
        }
        List<LayerConfiguration<?>> layerConfigurations = createLayerConfiguration(state);
        if (layerConfigurations == null) {
            LOGGER.info("Not sending messages");
            setLayerStackProcessingResult(new LayerStackProcessingResult(new LinkedList<>()));
            setExecuted(true);
        } else {
            if (hasDefaultAlias()) {
                LOGGER.info(
                        "Sending messages: {}",
                        LogPrinter.toHumanReadableOneLine(layerConfigurations));
            } else {
                LOGGER.info(
                        "Sending messages ({}): {}",
                        connectionAlias,
                        LogPrinter.toHumanReadableOneLine(layerConfigurations));
            }
            try {
                getSendResult(tlsContext.getLayerStack(), layerConfigurations);
                setExecuted(true);
            } catch (IOException e) {
                if (getActionOptions() == null
                        || !getActionOptions().contains(ActionOption.MAY_FAIL)) {
                    tlsContext.setReceivedTransportHandlerException(true);
                    LOGGER.debug(e);
                }
                setExecuted(true);
            }
        }
    }

    /**
     * Create a layer configuration for the send action. This function takes the tls context as
     * input as the configuration can depend on the current state of the connection. Note that this
     * function may change the context, and therefore, calling it twice in a row may lead to
     * distinct configurations. If an action does not wish to send messages, it can return null
     * here.
     *
     * @param state The current state
     * @return A list of layer configurations that should be executed.
     */
    protected abstract List<LayerConfiguration<?>> createLayerConfiguration(State state);

    @Override
    public final List<DtlsHandshakeMessageFragment> getSentFragments() {
        if (getLayerStackProcessingResult() == null) {
            return null;
        }
        return ActionHelperUtil.getDataContainersForLayer(
                        ImplementedLayers.DTLS_FRAGMENT, getLayerStackProcessingResult())
                .stream()
                .map(container -> (DtlsHandshakeMessageFragment) container)
                .collect(Collectors.toList());
    }

    @Override
    public final List<ProtocolMessage> getSentMessages() {
        if (getLayerStackProcessingResult() == null) {
            return null;
        }
        return ActionHelperUtil.getDataContainersForLayer(
                        ImplementedLayers.MESSAGE, getLayerStackProcessingResult())
                .stream()
                .map(container -> (ProtocolMessage) container)
                .collect(Collectors.toList());
    }

    @Override
    public final List<QuicFrame> getSentQuicFrames() {
        if (getLayerStackProcessingResult() == null) {
            return null;
        }
        return ActionHelperUtil.getDataContainersForLayer(
                        ImplementedLayers.QUICFRAME, getLayerStackProcessingResult())
                .stream()
                .map(container -> (QuicFrame) container)
                .collect(Collectors.toList());
    }

    @Override
    public final List<QuicPacket> getSentQuicPackets() {
        if (getLayerStackProcessingResult() == null) {
            return null;
        }
        return ActionHelperUtil.getDataContainersForLayer(
                        ImplementedLayers.QUICPACKET, getLayerStackProcessingResult())
                .stream()
                .map(container -> (QuicPacket) container)
                .collect(Collectors.toList());
    }

    @Override
    public final List<Record> getSentRecords() {
        if (getLayerStackProcessingResult() == null) {
            return null;
        }
        return ActionHelperUtil.getDataContainersForLayer(
                        ImplementedLayers.RECORD, getLayerStackProcessingResult())
                .stream()
                .map(container -> (Record) container)
                .collect(Collectors.toList());
    }

    @Override
    public boolean executedAsPlanned() {
        if (getLayerStackProcessingResult() != null) {
            return getLayerStackProcessingResult().executedAsPlanned();
        }
        return false;
    }
}
