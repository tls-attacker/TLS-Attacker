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

public class LayerStackFactory {

    public static LayerStack createLayerStack(LayerStackType type, TlsContext context) {

        switch (type) {
            case DTLS:
                throw new UnsupportedOperationException("Not implemented yet");
            case OPEN_VPN:
                throw new UnsupportedOperationException("Not implemented yet");
            case QUIC:
                throw new UnsupportedOperationException("Not implemented yet");
            case STARTTLS:
                throw new UnsupportedOperationException("Not implemented yet");
            case TLS:
                return new LayerStack(context, new MessageLayer(context), new RecordLayer(context),
                    new TcpLayer(context));
            case SSL2:
                throw new UnsupportedOperationException("Not implemented yet");
            default:
                throw new RuntimeException("Unknown LayerStackType: " + type.name());
        }
    }
}
