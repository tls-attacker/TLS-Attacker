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
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.layer.data.DataContainer;
import de.rub.nds.tlsattacker.core.layer.hints.LayerProcessingHint;
import de.rub.nds.tlsattacker.core.layer.stream.HintedInputStream;
import de.rub.nds.tlsattacker.core.layer.stream.HintedInputStreamAdapterStream;
import de.rub.nds.tlsattacker.transport.udp.UdpTransportHandler;
import java.io.IOException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * The UDP layer is a wrapper around an underlying UDP socket. It forwards the sockets InputStream
 * for reading and sends any data over the UDP layer without modifications.
 */
public class UdpLayer
        extends ProtocolLayer<LayerProcessingHint, DataContainer> { // TODO change types

    private static Logger LOGGER = LogManager.getLogger();

    private final TlsContext context;

    public UdpLayer(TlsContext context) {
        super(ImplementedLayers.UDP);
        this.context = context;
    }

    @Override
    public LayerProcessingResult sendConfiguration() throws IOException {
        LayerConfiguration<DataContainer> configuration = getLayerConfiguration();
        if (configuration != null && configuration.getContainerList() != null) {
            for (DataContainer container : configuration.getContainerList()) {
                // TODO Send container data
            }
        }
        return getLayerResult();
    }

    /** Sends data over the UDP socket. */
    @Override
    public LayerProcessingResult sendData(LayerProcessingHint hint, byte[] data)
            throws IOException {
        UdpTransportHandler handler = getTransportHandler();
        handler.sendData(data);
        return new LayerProcessingResult(null, getLayerType(), true); // Not implemented
    }

    @Override
    public void receiveMoreDataForHint(LayerProcessingHint hint) throws IOException {
        // There is nothing we can do here to fill up our stream, either there is data in it
        // or not
    }

    @Override
    public HintedInputStream getDataStream() {
        getTransportHandler().setTimeout(getTransportHandler().getTimeout());
        return new HintedInputStreamAdapterStream(null, getTransportHandler().getInputStream());
    }

    /** Returns the InputStream associated with the UDP socket. */
    @Override
    public LayerProcessingResult receiveData() {
        return new LayerProcessingResult(null, getLayerType(), true);
    }

    private UdpTransportHandler getTransportHandler() {
        if (context.getTransportHandler() == null) {
            throw new RuntimeException("TransportHandler is not set in context!");
        }
        if (!(context.getTransportHandler() instanceof UdpTransportHandler)) {
            throw new RuntimeException("Trying to set UDP layer with non UDP TransportHandler");
        }
        return (UdpTransportHandler) context.getTransportHandler();
    }
}
