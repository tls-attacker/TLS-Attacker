/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.layer;

import de.rub.nds.tlsattacker.core.constants.ChooserType;
import de.rub.nds.tlsattacker.core.layer.constant.LayerStackType;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.layer.context.TcpContext;
import de.rub.nds.tlsattacker.core.layer.impl.MessageLayer;
import de.rub.nds.tlsattacker.core.layer.impl.RecordLayer;
import de.rub.nds.tlsattacker.core.layer.impl.TcpLayer;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import de.rub.nds.tlsattacker.core.workflow.chooser.ChooserFactory;

public class LayerStackFactory {

    public static LayerStack createLayerStack(LayerStackType type, Context context) {

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
                // Chooser chooser = ChooserFactory.getChooser(ChooserType.DEFAULT, context, context.getConfig());
                // chooser.set
                // context.setChooser(chooser);
                TlsContext tlsContext = new TlsContext(context);
                TcpContext tcpContext = new TcpContext(context);
                LayerStack layerStack = new LayerStack(context, new MessageLayer(tlsContext),
                    new RecordLayer(tlsContext), new TcpLayer(tcpContext));
                context.setLayerStack(layerStack);
                return layerStack;
            default:
                throw new RuntimeException("Unknown LayerStackType: " + type.name());
        }
    }
}
