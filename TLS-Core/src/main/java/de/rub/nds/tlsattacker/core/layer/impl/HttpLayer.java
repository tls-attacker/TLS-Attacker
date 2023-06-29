/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.layer.impl;

import de.rub.nds.tlsattacker.core.exceptions.EndOfStreamException;
import de.rub.nds.tlsattacker.core.exceptions.TimeoutException;
import de.rub.nds.tlsattacker.core.http.HttpMessage;
import de.rub.nds.tlsattacker.core.http.HttpMessageSerializer;
import de.rub.nds.tlsattacker.core.http.HttpRequestMessage;
import de.rub.nds.tlsattacker.core.http.HttpResponseMessage;
import de.rub.nds.tlsattacker.core.layer.LayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.LayerProcessingResult;
import de.rub.nds.tlsattacker.core.layer.ProtocolLayer;
import de.rub.nds.tlsattacker.core.layer.constant.ImplementedLayers;
import de.rub.nds.tlsattacker.core.layer.context.HttpContext;
import de.rub.nds.tlsattacker.core.layer.hints.HttpLayerHint;
import de.rub.nds.tlsattacker.core.layer.hints.LayerProcessingHint;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.io.IOException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class HttpLayer extends ProtocolLayer<HttpLayerHint, HttpMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final HttpContext context;

    public HttpLayer(HttpContext context) {
        super(ImplementedLayers.HTTP);
        this.context = context;
    }

    @Override
    public LayerProcessingResult sendConfiguration() throws IOException {
        LayerConfiguration<HttpMessage> configuration = getLayerConfiguration();
        if (configuration != null && configuration.getContainerList() != null) {
            for (HttpMessage httpMsg : configuration.getContainerList()) {
                if (!prepareDataContainer(httpMsg, context)) {
                    continue;
                }
                httpMsg.getHandler(context).adjustContext(httpMsg);
                HttpMessageSerializer serializer = httpMsg.getSerializer(context);
                byte[] serializedMessage = serializer.serialize();
                getLowerLayer().sendData(null, serializedMessage);
                addProducedContainer(httpMsg);
            }
        }
        return getLayerResult();
    }

    @Override
    public LayerProcessingResult sendData(HttpLayerHint hint, byte[] additionalData)
            throws IOException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void receiveMoreDataForHint(LayerProcessingHint hint) throws IOException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public LayerProcessingResult receiveData() {
        try {
            do {
                // for now, we parse based on our endpoint
                if (context.getContext().getConnection().getLocalConnectionEndType()
                        == ConnectionEndType.CLIENT) {
                    HttpResponseMessage httpResponse = new HttpResponseMessage();
                    readDataContainer(httpResponse, context);
                } else {
                    HttpRequestMessage httpRequest = new HttpRequestMessage();
                    readDataContainer(httpRequest, context);
                }
                // receive until the layer configuration is satisfied or no data is left
            } while (shouldContinueProcessing());
        } catch (TimeoutException ex) {
            LOGGER.debug(ex);
        } catch (EndOfStreamException ex) {
            if (getLayerConfiguration() != null
                    && getLayerConfiguration().getContainerList() != null
                    && !getLayerConfiguration().getContainerList().isEmpty()) {
                LOGGER.debug("Reached end of stream, cannot parse more messages", ex);
            } else {
                LOGGER.debug("No messages required for layer.");
            }
        }

        return getLayerResult();
    }
}
