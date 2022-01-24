/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.layer;

import de.rub.nds.tlsattacker.core.layer.constant.ProtocolLayer;
import de.rub.nds.tlsattacker.core.layer.context.HttpContext;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.layer.context.TcpContext;
import de.rub.nds.tlsattacker.core.layer.impl.HttpLayer;
import de.rub.nds.tlsattacker.core.layer.impl.MessageLayer;
import de.rub.nds.tlsattacker.core.layer.impl.RecordLayer;
import de.rub.nds.tlsattacker.core.layer.impl.TcpLayer;
import de.rub.nds.tlsattacker.core.state.Context;

public class LayerStackFactory {

    public static LayerStack createLayerStack(ProtocolLayer type, Context context) {

        LayerStack layerStack;
        TlsContext tlsContext;
        TcpContext tcpContext;
        HttpContext httpContext;

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
                tlsContext = new TlsContext(context);
                tcpContext = new TcpContext(context);
                layerStack = new LayerStack(context, new MessageLayer(tlsContext), new RecordLayer(tlsContext),
                    new TcpLayer(tcpContext));
                context.setLayerStack(layerStack);
                return layerStack;
            case HTTPS:
                tlsContext = new TlsContext(context);
                tcpContext = new TcpContext(context);
                httpContext = new HttpContext(context);
                layerStack = new LayerStack(context, new HttpLayer(httpContext), new MessageLayer(tlsContext),
                    new RecordLayer(tlsContext), new TcpLayer(tcpContext));
                context.setLayerStack(layerStack);
                return layerStack;

            default:
                throw new RuntimeException("Unknown LayerStackType: " + type.name());
        }
    }
}
