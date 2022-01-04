/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 * <p>
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.layer.impl;

import de.rub.nds.tlsattacker.core.https.HttpsRequestMessage;
import de.rub.nds.tlsattacker.core.https.HttpsResponseMessage;
import de.rub.nds.tlsattacker.core.layer.DataContainer;
import de.rub.nds.tlsattacker.core.layer.LayerProcessingResult;
import de.rub.nds.tlsattacker.core.layer.ProtocolLayer;
import de.rub.nds.tlsattacker.core.layer.hints.LayerProcessingHint;
import de.rub.nds.tlsattacker.core.layer.stream.HintedInputStream;
import de.rub.nds.tlsattacker.core.layer.stream.HintedLayerInputStream;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

//TODO Separate HTTP messages from protocol layer
public class HttpLayer extends ProtocolLayer<LayerProcessingHint, DataContainer> {

    // TODO Exchange with generic/http context
    private TlsContext context;

    public HttpLayer(TlsContext context) {
        this.context = context;
    }

    @Override
    public LayerProcessingResult sendConfiguration() throws IOException {
        throw new UnsupportedOperationException("Not supported yet."); // To change body of generated methods, choose
        // Tools | Templates.
    }

    @Override
    public LayerProcessingResult sendData(LayerProcessingHint hint, byte[] additionalData) throws IOException {
        throw new UnsupportedOperationException("Not supported yet."); // To change body of generated methods, choose
        // Tools | Templates.
    }

    @Override
    public void receiveMoreDataForHint(LayerProcessingHint hint) throws IOException {
        HintedInputStream dataStream = getLowerLayer().getDataStream();
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        while (dataStream.available() > 0) {
            if (context.getTalkingConnectionEndType() == ConnectionEndType.CLIENT) {
                HttpsRequestMessage message = new HttpsRequestMessage();
                message.getParser(context, dataStream);
                addProducedContainer(message);
                // TODO we are currently not passing client requests upwards
            } else {
                // Server talking
                HttpsResponseMessage message = new HttpsResponseMessage();
                message.getParser(context, dataStream);
                addProducedContainer(message);
                outputStream.write(message.getResponseContent().getValue().getBytes(StandardCharsets.ISO_8859_1));
            }
        }
        dataStream.extendStream(outputStream.toByteArray());
    }

    @Override
    public HintedLayerInputStream getDataStream() {
        return new HintedLayerInputStream(null, this);
    }

    @Override
    public LayerProcessingResult receiveData() throws IOException {
        throw new UnsupportedOperationException("Not supported yet."); // To change body of generated methods, choose
        // Tools | Templates.
    }
}
