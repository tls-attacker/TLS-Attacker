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
import de.rub.nds.tlsattacker.core.tcp.TcpStreamContainer;
import de.rub.nds.tlsattacker.transport.tcp.TcpTransportHandler;
import java.io.ByteArrayInputStream;
import java.io.IOException;

/**
 * The TCP layer is a wrapper around an underlying TCP socket. It forwards the sockets InputStream
 * for reading and sends any data over the TCP socket without modifications.
 */
public class TcpLayer extends ProtocolLayer<Context, LayerProcessingHint, TcpStreamContainer> {

    private final Context context;

    public TcpLayer(Context context) {
        super(ImplementedLayers.TCP);
        this.context = context;
    }

    @Override
    public LayerProcessingResult<TcpStreamContainer> sendConfiguration() throws IOException {
        LayerConfiguration<TcpStreamContainer> configuration = getLayerConfiguration();
        if (configuration != null) {
            for (TcpStreamContainer container : getUnprocessedConfiguredContainers()) {
                prepareDataContainer(container, context);
                addProducedContainer(container);
                TcpTransportHandler handler = getTransportHandler();
                handler.sendData(container.getSerializer(context).serialize());
            }
        }
        return getLayerResult();
    }

    /** Sends data over the TCP socket. */
    @Override
    public LayerProcessingResult<TcpStreamContainer> sendData(LayerProcessingHint hint, byte[] data)
            throws IOException {
        TcpStreamContainer container;
        if (getUnprocessedConfiguredContainers().isEmpty()) {
            container = new TcpStreamContainer();
        } else {
            container = getUnprocessedConfiguredContainers().get(0);
        }
        container.setConfigData(data);
        prepareDataContainer(container, context);
        addProducedContainer(container);
        TcpTransportHandler handler = getTransportHandler();
        handler.sendData(container.getSerializer(context).serialize());
        return getLayerResult();
    }

    @Override
    public void receiveMoreDataForHint(LayerProcessingHint hint) throws IOException {
        // There is nothing we can do here to fill up our stream, either there is data in it
        // or not
        byte[] receivedTcpData = getTransportHandler().fetchData();

        TcpStreamContainer tcpStreamContainer = new TcpStreamContainer();
        tcpStreamContainer
                .getParser(context, new ByteArrayInputStream(receivedTcpData))
                .parse(tcpStreamContainer);
        tcpStreamContainer.getPreparator(context).prepareAfterParse();
        tcpStreamContainer.getHandler(context).adjustContext(tcpStreamContainer);
        addProducedContainer(tcpStreamContainer);
        if (currentInputStream == null) {
            currentInputStream = new HintedLayerInputStream(null, this);
            currentInputStream.extendStream(receivedTcpData);
        } else {
            currentInputStream.extendStream(receivedTcpData);
        }
    }

    @Override
    public LayerProcessingResult<TcpStreamContainer> receiveData() {
        return new LayerProcessingResult<>(null, getLayerType(), true);
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
