/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.protocol.message.HeartbeatMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;

/**
 * Handler for Heartbeat messages: http://tools.ietf.org/html/rfc6520#page-4
 */
public class HeartbeatMessageHandler extends TlsMessageHandler<HeartbeatMessage> {

    public HeartbeatMessageHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public void adjustTLSContext(HeartbeatMessage message) {
        // TODO perhaps something to do here
    }
}
