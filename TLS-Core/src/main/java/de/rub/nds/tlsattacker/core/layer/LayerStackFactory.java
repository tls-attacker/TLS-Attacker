/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.layer;

import de.rub.nds.tlsattacker.core.layer.constant.StackConfiguration;
import de.rub.nds.tlsattacker.core.layer.context.*;
import de.rub.nds.tlsattacker.core.layer.impl.*;
import de.rub.nds.tlsattacker.core.state.Context;

/**
 * Creates a layerStack based on pre-defined configurations. E.g., to send TLS messages with
 * TLS-Attacker, we have to produce a layerStack that contains the MessageLayer, RecordLayer, and
 * TcpLayer. Each layer is assigned a different context.
 */
public class LayerStackFactory {

    public static LayerStack createLayerStack(StackConfiguration type, Context context) {

        LayerStack layerStack;
        switch (type) {
            case OPEN_VPN:
            case STARTTLS:
                throw new UnsupportedOperationException("Not implemented yet");

            case DTLS:
                return new LayerStack(
                        context,
                        new MessageLayer(context),
                        new DtlsFragmentLayer(context),
                        new RecordLayer(context),
                        new UdpLayer(context));
            case QUIC:
                return new LayerStack(
                        context,
                        new MessageLayer(context),
                        new QuicFrameLayer(context),
                        new QuicPacketLayer(context),
                        new UdpLayer(context));
            case TLS:
                layerStack =
                        new LayerStack(
                                context,
                                new MessageLayer(context),
                                new RecordLayer(context),
                                new TcpLayer(context));
                context.setLayerStack(layerStack);
                return layerStack;
            case HTTPS:
                layerStack =
                        new LayerStack(
                                context,
                                new HttpLayer(context),
                                new MessageLayer(context),
                                new RecordLayer(context),
                                new TcpLayer(context));
                return layerStack;
            case POP3:
                layerStack =
                        new LayerStack(
                                context,
                                new Pop3Layer(context),
                                new MessageLayer(context, false),
                                new RecordLayer(context, false),
                                new TcpLayer(context));
                return layerStack;
            case POP3S:
                layerStack =
                        new LayerStack(
                                context,
                                new Pop3Layer(context),
                                new MessageLayer(context),
                                new RecordLayer(context),
                                new TcpLayer(context));
                return layerStack;
            case SMTP:
                layerStack =
                        new LayerStack(
                                context,
                                new SmtpLayer(context),
                                new MessageLayer(context, false),
                                new RecordLayer(context, false),
                                new TcpLayer(context));
                return layerStack;
            case SMTPS:
                layerStack =
                        new LayerStack(
                                context,
                                new SmtpLayer(context),
                                new MessageLayer(context),
                                new RecordLayer(context),
                                new TcpLayer(context));
                return layerStack;
            case SSL2:
                layerStack = new LayerStack(context, new SSL2Layer(context), new TcpLayer(context));
                return layerStack;

            default:
                throw new RuntimeException("Unknown LayerStackType: " + type.name());
        }
    }
}
