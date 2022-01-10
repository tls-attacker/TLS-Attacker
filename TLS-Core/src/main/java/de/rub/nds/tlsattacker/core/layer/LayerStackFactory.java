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
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.TlsContext;

public class LayerStackFactory {

    public static LayerStack createLayerStack(LayerStackType type, Context context) {

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
                return new LayerStack(context, new MessageLayer(context.getMessageContext()),
                        new RecordLayer(context.getRecordContext()), new TcpLayer(context.getTcpContext()));
            default:
                throw new RuntimeException("Unknown LayerStackType: " + type.name());
        }
    }
}
