/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tcp.TcpStreamContainer;
import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.http.HttpMessage;
import de.rub.nds.tlsattacker.core.layer.LayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.constant.ImplementedLayers;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.printer.LogPrinter;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import de.rub.nds.tlsattacker.core.protocol.message.SSL2Message;
import de.rub.nds.tlsattacker.core.quic.frame.QuicFrame;
import de.rub.nds.tlsattacker.core.quic.packet.QuicPacket;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import de.rub.nds.tlsattacker.core.workflow.container.ActionHelperUtil;
import de.rub.nds.udp.UdpDataPacket;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

public abstract class CommonReceiveAction extends MessageAction implements ReceivingAction {

    public CommonReceiveAction() {
        super();
    }

    public CommonReceiveAction(String connectionAlias) {
        super(connectionAlias);
    }

    public CommonReceiveAction(Set<ActionOption> actionOptions, String connectionAlias) {
        super(actionOptions, connectionAlias);
    }

    public CommonReceiveAction(Set<ActionOption> actionOptions) {
        super(actionOptions);
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        TlsContext tlsContext = state.getTlsContext(getConnectionAlias());

        if (isExecuted()) {
            throw new ActionExecutionException("Action already executed!");
        }

        LOGGER.debug("Receiving... (" + this.getClass().getSimpleName() + ")");
        List<LayerConfiguration<?>> layerConfigurations = createLayerConfiguration(state);
        getReceiveResult(tlsContext.getLayerStack(), layerConfigurations);
        setExecuted(true);
        LOGGER.debug(
                "Receive Expected: {}", LogPrinter.toHumanReadableOneLine(layerConfigurations));

        if (hasDefaultAlias()) {
            LOGGER.info(
                    "Received Messages: {}",
                    LogPrinter.toHumanReadableMultiLine(getLayerStackProcessingResult()));
        } else {
            LOGGER.info(
                    "Received Messages ({}): {}",
                    getConnectionAlias(),
                    LogPrinter.toHumanReadableMultiLine(getLayerStackProcessingResult()));
        }
    }

    @Override
    public final MessageActionDirection getMessageDirection() {
        return MessageActionDirection.RECEIVING;
    }

    @Override
    public Set<String> getAllReceivingAliases() {
        return new HashSet<>(Collections.singleton(connectionAlias));
    }

    protected abstract List<LayerConfiguration<?>> createLayerConfiguration(State state);

    @Override
    public List<ProtocolMessage> getReceivedMessages() {
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
    public List<SSL2Message> getReceivedSSL2Messages() {
        if (getLayerStackProcessingResult() == null) {
            return null;
        }
        return ActionHelperUtil.getDataContainersForLayer(
                        ImplementedLayers.SSL2, getLayerStackProcessingResult())
                .stream()
                .map(container -> (SSL2Message) container)
                .collect(Collectors.toList());
    }

    @Override
    public List<Record> getReceivedRecords() {
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
    public List<DtlsHandshakeMessageFragment> getReceivedFragments() {
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
    public List<HttpMessage> getReceivedHttpMessages() {
        if (getLayerStackProcessingResult() == null) {
            return null;
        }
        return ActionHelperUtil.getDataContainersForLayer(
                        ImplementedLayers.HTTP, getLayerStackProcessingResult())
                .stream()
                .map(container -> (HttpMessage) container)
                .collect(Collectors.toList());
    }

    @Override
    public List<QuicFrame> getReceivedQuicFrames() {
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
    public List<QuicPacket> getReceivedQuicPackets() {
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
    public List<TcpStreamContainer> getReceivedTcpStreamContainers() {
        if (getLayerStackProcessingResult() == null) {
            return null;
        }
        return ActionHelperUtil.getDataContainersForLayer(
                        ImplementedLayers.TCP, getLayerStackProcessingResult())
                .stream()
                .map(container -> (TcpStreamContainer) container)
                .collect(Collectors.toList());
    }

    @Override
    public List<UdpDataPacket> getReceivedUdpDataPackets() {
        if (getLayerStackProcessingResult() == null) {
            return null;
        }
        return ActionHelperUtil.getDataContainersForLayer(
                        ImplementedLayers.UDP, getLayerStackProcessingResult())
                .stream()
                .map(container -> (UdpDataPacket) container)
                .collect(Collectors.toList());
    }

    @Override
    public boolean executedAsPlanned() {
        if (this.isExecuted() && getLayerStackProcessingResult() != null) {
            return getLayerStackProcessingResult().executedAsPlanned();
        }
        return false;
    }
}
