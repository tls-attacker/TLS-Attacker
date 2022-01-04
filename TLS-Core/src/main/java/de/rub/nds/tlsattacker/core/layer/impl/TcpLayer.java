/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.layer.impl;

import de.rub.nds.tlsattacker.core.layer.DataContainer;
import de.rub.nds.tlsattacker.core.layer.LayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.LayerProcessingResult;
import de.rub.nds.tlsattacker.core.layer.ProtocolLayer;
import de.rub.nds.tlsattacker.core.layer.hints.LayerProcessingHint;
import de.rub.nds.tlsattacker.core.layer.stream.HintedInputStream;
import de.rub.nds.tlsattacker.core.layer.stream.HintedInputStreamAdapterStream;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.tcp.TcpTransportHandler;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;

public class TcpLayer extends ProtocolLayer<LayerProcessingHint, DataContainer> {// TODO change types

    private static Logger LOGGER = LogManager.getLogger();

    private final TlsContext context;

    public TcpLayer(TlsContext context) {
        this.context = context;
    }

    @Override
    public LayerProcessingResult sendConfiguration() throws IOException {
        LayerConfiguration<DataContainer> configuration = getLayerConfiguration();
        if (configuration.getContainerList() != null) {
            for (DataContainer container : configuration.getContainerList()) {
                // TODO Send container data
            }
        }
        return getLayerResult();
    }

    @Override
    public LayerProcessingResult sendData(LayerProcessingHint hint, byte[] data) throws IOException {
        TcpTransportHandler handler = getTransportHandler();
        if (handler.getOutputStream() == null) {
            throw new RuntimeException("TCP Layer not initialized");
        }
        handler.getOutputStream().write(data);
        handler.getOutputStream().flush();
        return new LayerProcessingResult(null);// Not implemented
    }

    @Override
    public void receiveMoreDataForHint(LayerProcessingHint hint) throws IOException {
        // There is nothing we can do here to fill up our stream, either there is data in it
        // or not
    }

    @Override
    public HintedInputStream getDataStream() {
        return new HintedInputStreamAdapterStream(null, getTransportHandler().getInputStream());
    }

    @Override
    public LayerProcessingResult receiveData() throws IOException {
        return new LayerProcessingResult(null);
    }

    private TcpTransportHandler getTransportHandler() {
        if (context.getTransportHandler() == null) {
            throw new RuntimeException("TransportHandler is not set in context!");
        }
        if (!(context.getTransportHandler() instanceof TcpTransportHandler)) {
            throw new RuntimeException("Trying to set TCP layer with non TCP TransportHandler");
        }
        return (TcpTransportHandler) context.getTransportHandler();
    }
}
