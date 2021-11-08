
package de.rub.nds.tlsattacker.core.layer.impl;

import de.rub.nds.tlsattacker.core.layer.DataContainer;
import de.rub.nds.tlsattacker.core.layer.LayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.hints.LayerProcessingHint;
import de.rub.nds.tlsattacker.core.layer.LayerProcessingResult;
import de.rub.nds.tlsattacker.core.layer.ProtocolLayer;
import de.rub.nds.tlsattacker.core.layer.stream.HintedLayerStream;
import java.io.IOException;
import java.net.Socket;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class TcpLayer extends ProtocolLayer<LayerProcessingHint, DataContainer> {// TODO change types

    private static Logger LOGGER = LogManager.getLogger();

    private final Socket socket;

    public TcpLayer(Socket socket) {
        this.socket = socket;
    }

    @Override
    public LayerProcessingResult sendData(byte[] data) throws IOException {
        return sendData(null, data);// no hint needed
    }

    @Override
    public LayerProcessingResult sendData() throws IOException {
        LayerConfiguration<DataContainer> configuration = getLayerConfiguration();
        for (DataContainer container : configuration.getContainerList()) {
            // TODO Send container data
        }
        throw new UnsupportedOperationException("Implement configureable TCP packet container");
    }

    @Override
    public LayerProcessingResult sendData(LayerProcessingHint hint) throws IOException {
        LayerConfiguration<DataContainer> configuration = getLayerConfiguration();
        for (DataContainer container : configuration.getContainerList()) {
            // TODO Send container data
        }
        throw new UnsupportedOperationException("Implement configureable TCP packet container");
    }

    @Override
    public LayerProcessingResult sendData(LayerProcessingHint hint, byte[] data) throws IOException {
        socket.getOutputStream().write(data);
        getResultDataStream().write(data);
        return new LayerProcessingResult(null, null);// Not implemented
    }

    @Override
    public byte[] retrieveMoreData(LayerProcessingHint hint) throws IOException {
        byte[] data = new byte[socket.getInputStream().available()];
        socket.getInputStream().read(data);
        getResultDataStream().write(data);
        return data;
    }

    @Override
    public HintedLayerStream getDataStream() {
        return new HintedLayerStream(null, this);
    }
}
