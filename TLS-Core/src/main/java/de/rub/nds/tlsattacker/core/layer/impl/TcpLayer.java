package de.rub.nds.tlsattacker.core.layer.impl;

import de.rub.nds.tlsattacker.core.layer.LayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.LayerProcessingResult;
import de.rub.nds.tlsattacker.core.layer.ProtocolLayer;
import de.rub.nds.tlsattacker.transport.tcp.TcpTransportHandler;
import java.io.IOException;
import java.util.logging.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class TcpLayer extends ProtocolLayer {

    private static Logger LOGGER = LogManager.getLogger();

    private TcpTransportHandler tcpTransportHandler;

    public TcpLayer(TcpTransportHandler tcpTransportHandler) {
        this.tcpTransportHandler = tcpTransportHandler;
    }

    @Override
    public LayerProcessingResult sendConfiguration(LayerConfiguration configuration) {
        if (configuration.getContainerList() != null) {
            LOGGER.warn("TCP layer containers are not supported yet. Ignoring");
        }
        try {
            tcpTransportHandler.sendData(configuration.getAdditionalLayerData());
        } catch (IOException ex) {
            throw new RuntimeException(ex);
        }
    }

    @Override
    public LayerProcessingResult receiveConfiguration(LayerConfiguration configuration) {
        try {
            byte[] fetchData = tcpTransportHandler.fetchData();
            return new LayerProcessingResult(null, fetchData);
        } catch (IOException ex) {
            throw new RuntimeException(ex);
        }
    }

}
