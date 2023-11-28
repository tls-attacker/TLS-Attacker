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
import de.rub.nds.tlsattacker.core.http.HttpMessage;
import de.rub.nds.tlsattacker.core.layer.LayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.LayerProcessingResult;
import de.rub.nds.tlsattacker.core.layer.constant.ImplementedLayers;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import de.rub.nds.tlsattacker.core.quic.frame.QuicFrame;
import de.rub.nds.tlsattacker.core.quic.packet.QuicPacket;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.state.State;
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

    @Override
    public void execute(State state) throws ActionExecutionException {
        TlsContext tlsContext = state.getTlsContext(getConnectionAlias());

        if (isExecuted()) {
            throw new ActionExecutionException("Action already executed!");
        }

        LOGGER.debug("Receiving... (" + this.getClass().getSimpleName() + ")");
        List<LayerConfiguration> layerConfigurations = createLayerConfiguration(tlsContext);
        getReceiveResult(tlsContext.getLayerStack(), layerConfigurations);
        setExecuted(true);

        String expected = getReadableStringFromConfiguration(layerConfigurations);
        LOGGER.debug("Receive Expected: {}", expected);
        String received = getReadableString(getLayerStackProcessingResult());
        if (hasDefaultAlias()) {
            LOGGER.info("Received Messages: {}", received);
        } else {
            LOGGER.info("Received Messages ({}): {}", getConnectionAlias(), received);
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

    protected abstract List<LayerConfiguration> createLayerConfiguration(TlsContext tlsContext);

    @Override
    public List<ProtocolMessage> getReceivedMessages() {
        return getDataContainersForLayer(ImplementedLayers.MESSAGE).stream()
                .map(container -> (ProtocolMessage) container)
                .collect(Collectors.toList());
    }

    @Override
    public List<Record> getReceivedRecords() {
        return getDataContainersForLayer(ImplementedLayers.RECORD).stream()
                .map(container -> (Record) container)
                .collect(Collectors.toList());
    }

    @Override
    public List<DtlsHandshakeMessageFragment> getReceivedFragments() {
        return getDataContainersForLayer(ImplementedLayers.DTLS_FRAGMENT).stream()
                .map(container -> (DtlsHandshakeMessageFragment) container)
                .collect(Collectors.toList());
    }

    @Override
    public List<HttpMessage> getReceivedHttpMessages() {
        return getDataContainersForLayer(ImplementedLayers.HTTP).stream()
                .map(container -> (HttpMessage) container)
                .collect(Collectors.toList());
    }

    @Override
    public List<QuicFrame> getReceivedQuicFrames() {
        return getDataContainersForLayer(ImplementedLayers.QUICFRAME).stream()
                .map(container -> (QuicFrame) container)
                .collect(Collectors.toList());
    }

    @Override
    public List<QuicPacket> getReceivedQuicPackets() {
        return getDataContainersForLayer(ImplementedLayers.QUICPACKET).stream()
                .map(container -> (QuicPacket) container)
                .collect(Collectors.toList());
    }

    @Override
    public boolean executedAsPlanned() {
        if (getLayerStackProcessingResult() != null) {
            for (LayerProcessingResult result :
                    getLayerStackProcessingResult().getLayerProcessingResultList()) {
                if (!result.isExecutedAsPlanned()) {
                    LOGGER.warn(
                            "{} failed: Layer {}, did not execute as planned",
                            this.getClass().getSimpleName(),
                            result.getLayerType());
                    return false;
                }
            }
            return true;
        }
        return false;
    }
}
