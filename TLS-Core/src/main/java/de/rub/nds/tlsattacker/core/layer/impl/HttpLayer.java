/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.layer.impl;

import de.rub.nds.tlsattacker.core.http.HttpRequestMessage;
import de.rub.nds.tlsattacker.core.http.HttpResponseMessage;
import de.rub.nds.tlsattacker.core.layer.constant.ImplementedLayers;
import de.rub.nds.tlsattacker.core.layer.data.DataContainer;
import de.rub.nds.tlsattacker.core.layer.LayerProcessingResult;
import de.rub.nds.tlsattacker.core.layer.ProtocolLayer;
import de.rub.nds.tlsattacker.core.layer.constant.LayerType;
import de.rub.nds.tlsattacker.core.layer.context.HttpContext;
import de.rub.nds.tlsattacker.core.layer.hints.LayerProcessingHint;
import de.rub.nds.tlsattacker.core.layer.stream.HintedInputStream;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * The HTTPLayer handles HTTP data. Currently WIP
 */
public class HttpLayer extends ProtocolLayer<LayerProcessingHint, DataContainer> {

    private final HttpContext context;

    public HttpLayer(HttpContext context) {
        super(ImplementedLayers.HTTP);
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
                HttpRequestMessage message = new HttpRequestMessage();
                message.getParser(context, dataStream);
                addProducedContainer(message);
                // TODO we are currently not passing client requests upwards
            } else {
                // Server talking
                HttpResponseMessage message = new HttpResponseMessage();
                message.getParser(context, dataStream);
                addProducedContainer(message);
                outputStream.write(message.getResponseContent().getValue().getBytes(StandardCharsets.ISO_8859_1));
            }
        }
        dataStream.extendStream(outputStream.toByteArray());
    }

    @Override
    public LayerProcessingResult receiveData() throws IOException {
        throw new UnsupportedOperationException("Not supported yet."); // To change body of generated methods, choose
        // Tools | Templates.
    }
}
