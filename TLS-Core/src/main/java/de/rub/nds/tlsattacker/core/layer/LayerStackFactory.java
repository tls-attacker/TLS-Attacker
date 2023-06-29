/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.layer;

import de.rub.nds.tlsattacker.core.layer.constant.LayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.context.HttpContext;
import de.rub.nds.tlsattacker.core.layer.context.TcpContext;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.layer.impl.*;
import de.rub.nds.tlsattacker.core.state.Context;

/**
 * Creates a layerStack based on pre-defined configurations. E.g., to send TLS messages with
 * TLS-Attacker, we have to produce a layerStack that contains the MessageLayer, RecordLayer, and
 * TcpLayer. Each layer is assigned a different context.
 */
public class LayerStackFactory {

    public static LayerStack createLayerStack(LayerConfiguration type, Context context) {

        LayerStack layerStack;
        TlsContext tlsContext = context.getTlsContext();
        TcpContext tcpContext = context.getTcpContext();
        HttpContext httpContext = context.getHttpContext();

        switch (type) {
            case OPEN_VPN:
            case QUIC:
            case STARTTLS:
                throw new UnsupportedOperationException("Not implemented yet");
            case DTLS:
                return new LayerStack(
                        context,
                        new MessageLayer(tlsContext),
                        new DtlsFragmentLayer(tlsContext),
                        new RecordLayer(tlsContext),
                        new UdpLayer(tlsContext));
            case TLS:
                layerStack =
                        new LayerStack(
                                context,
                                new MessageLayer(tlsContext),
                                new RecordLayer(tlsContext),
                                new TcpLayer(tcpContext));
                context.setLayerStack(layerStack);
                return layerStack;
            case HTTPS:
                layerStack =
                        new LayerStack(
                                context,
                                new HttpLayer(httpContext),
                                new MessageLayer(tlsContext),
                                new RecordLayer(tlsContext),
                                new TcpLayer(tcpContext));
                return layerStack;
            case SSL2:
                layerStack =
                        new LayerStack(
                                context, new SSL2Layer(tlsContext), new TcpLayer(tcpContext));
                return layerStack;

            default:
                throw new RuntimeException("Unknown LayerStackType: " + type.name());
        }
    }
}
