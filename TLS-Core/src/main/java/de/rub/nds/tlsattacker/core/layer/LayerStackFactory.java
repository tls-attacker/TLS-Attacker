/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.layer;

import de.rub.nds.tlsattacker.core.layer.constant.LayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.context.HttpContext;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.layer.context.TcpContext;
import de.rub.nds.tlsattacker.core.layer.impl.HttpLayer;
import de.rub.nds.tlsattacker.core.layer.impl.MessageLayer;
import de.rub.nds.tlsattacker.core.layer.impl.RecordLayer;
import de.rub.nds.tlsattacker.core.layer.impl.TcpLayer;
import de.rub.nds.tlsattacker.core.state.Context;

/**
 * Creates a layerStack based on pre-defined configurations. E.g., to send TLS messages with TLS-Attacker, we have to
 * produce a layerStack that contains the MessageLayer, RecordLayer, and TcpLayer. All share the same context.
 */
public class LayerStackFactory {

    public static LayerStack createLayerStack(LayerConfiguration type, Context context) {

        LayerStack layerStack;
        TlsContext tlsContext = context.getTlsContext();
        TcpContext tcpContext = context.getTcpContext();
        HttpContext httpContext = context.getHttpContext();

        switch (type) {
            case DTLS:
            case OPEN_VPN:
            case QUIC:
            case STARTTTLS:
                throw new UnsupportedOperationException("Not implemented yet");
            case TLS:
                /*
                 * initialize layer contexts
                 */
                layerStack = new LayerStack(context, new MessageLayer(tlsContext), new RecordLayer(tlsContext),
                    new TcpLayer(tcpContext));
                context.setLayerStack(layerStack);
                return layerStack;
            case HTTPS:
                layerStack = new LayerStack(context, new HttpLayer(httpContext), new MessageLayer(tlsContext),
                    new RecordLayer(tlsContext), new TcpLayer(tcpContext));
                return layerStack;

            default:
                throw new RuntimeException("Unknown LayerStackType: " + type.name());
        }
    }
}
