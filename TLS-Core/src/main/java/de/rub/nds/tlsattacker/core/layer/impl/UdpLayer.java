/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.layer.impl;

import de.rub.nds.tlsattacker.core.layer.LayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.LayerProcessingResult;
import de.rub.nds.tlsattacker.core.layer.ProtocolLayer;
import de.rub.nds.tlsattacker.core.layer.constant.ImplementedLayers;
import de.rub.nds.tlsattacker.core.layer.hints.LayerProcessingHint;
import de.rub.nds.tlsattacker.core.layer.stream.HintedLayerInputStream;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.udp.UdpDataPacket;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import de.rub.nds.tlsattacker.transport.udp.UdpTransportHandler;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * The UDP layer is a wrapper around an underlying UDP socket. It forwards the sockets InputStream
 * for reading and sends any data over the UDP layer without modifications.
 */
public class UdpLayer extends ProtocolLayer<LayerProcessingHint, UdpDataPacket> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final Context context;

    public UdpLayer(Context context) {
        super(ImplementedLayers.UDP);
        this.context = context;
    }

    @Override
    public LayerProcessingResult<UdpDataPacket> sendConfiguration() throws IOException {
        LayerConfiguration<UdpDataPacket> configuration = getLayerConfiguration();
        if (configuration != null) {
            for (UdpDataPacket udpDataPacket : getUnprocessedConfiguredContainers()) {
                prepareDataContainer(udpDataPacket, context);
                addProducedContainer(udpDataPacket);
                TransportHandler handler = getTransportHandler();
                handler.sendData(udpDataPacket.getSerializer(context).serialize());
            }
        }
        return getLayerResult();
    }

    /** Sends data over the UDP socket. */
    @Override
    public LayerProcessingResult<UdpDataPacket> sendData(LayerProcessingHint hint, byte[] data)
            throws IOException {
        UdpDataPacket udpDataPacket;
        if (getUnprocessedConfiguredContainers().isEmpty()) {
            udpDataPacket = new UdpDataPacket();
        } else {
            udpDataPacket = getUnprocessedConfiguredContainers().get(0);
        }
        udpDataPacket.setConfigData(data);
        prepareDataContainer(udpDataPacket, context);
        addProducedContainer(udpDataPacket);
        TransportHandler handler = getTransportHandler();
        handler.sendData(udpDataPacket.getSerializer(context).serialize());
        return getLayerResult();
    }

    @Override
    public void receiveMoreDataForHint(LayerProcessingHint hint) throws IOException {
        byte[] receivedPacket = getTransportHandler().fetchData();
        LOGGER.debug("Received packet: {}", receivedPacket);
        UdpDataPacket udpDataPacket = new UdpDataPacket();
        udpDataPacket
                .getParser(context, new ByteArrayInputStream(receivedPacket))
                .parse(udpDataPacket);
        udpDataPacket.getPreparator(context).prepareAfterParse();
        udpDataPacket.getHandler(context).adjustContext(udpDataPacket);
        addProducedContainer(udpDataPacket);
        if (currentInputStream == null || currentInputStream.available() == 0) {
            currentInputStream = new HintedLayerInputStream(null, this);
            currentInputStream.extendStream(receivedPacket);
        } else {
            if (nextInputStream == null) {
                nextInputStream = new HintedLayerInputStream(null, this);
            }
            nextInputStream.extendStream(receivedPacket);
        }
    }

    @Override
    public LayerProcessingResult<UdpDataPacket> receiveData() {
        return new LayerProcessingResult<>(null, getLayerType(), true);
    }

    private TransportHandler getTransportHandler() {
        if (context.getTransportHandler() == null) {
            throw new RuntimeException("TransportHandler is not set in context!");
        }
        if (!(context.getTransportHandler() instanceof UdpTransportHandler)) {
            LOGGER.warn("UDP layer with non UDP TransportHandler");
        }
        return context.getTransportHandler();
    }
}
