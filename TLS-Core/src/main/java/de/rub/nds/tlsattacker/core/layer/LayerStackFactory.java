/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.layer;

import de.rub.nds.tlsattacker.core.layer.constant.LayerStackType;
import de.rub.nds.tlsattacker.core.layer.impl.MessageLayer;
import de.rub.nds.tlsattacker.core.layer.impl.RecordLayer;
import de.rub.nds.tlsattacker.core.layer.impl.TcpLayer;
import de.rub.nds.tlsattacker.core.state.TlsContext;

/**
 * Creates a layerStack based on pre-defined configurations. E.g., to send TLS messages with TLS-Attacker, we
 * have to produce a layerStack that contains the MessageLayer, RecordLayer, and TcpLayer. All share the same context.
 */
public class LayerStackFactory {

    public static LayerStack createLayerStack(LayerStackType type, TlsContext context) {

        switch (type) {
            case DTLS:
                throw new UnsupportedOperationException("Not implemented yet");
            case OPEN_VPN:
                throw new UnsupportedOperationException("Not implemented yet");
            case QUIC:
                throw new UnsupportedOperationException("Not implemented yet");
            case STARTTTLS:
                throw new UnsupportedOperationException("Not implemented yet");
            case TLS:
                return new LayerStack(context, new MessageLayer(context), new RecordLayer(context),
                    new TcpLayer(context));
            default:
                throw new RuntimeException("Unknown LayerStackType: " + type.name());
        }
    }
}
