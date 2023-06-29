/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.layer.context;

import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.transport.socket.SocketState;

/** Holds all runtime variables of the TCPLayer. */
public class TcpContext extends LayerContext {

    private SocketState finalSocketState;

    public TcpContext(Context context) {
        super(context);
        context.setTcpContext(this);
    }

    public SocketState getFinalSocketState() {
        return finalSocketState;
    }

    public void setFinalSocketState(SocketState finalSocketState) {
        this.finalSocketState = finalSocketState;
    }
}
