/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;

/**


 * @param <ProtocolMessage>
 */
public abstract class HandshakeMessageHandler<ProtocolMessage extends HandshakeMessage> extends
        ProtocolMessageHandler<ProtocolMessage> {

    public HandshakeMessageHandler(TlsContext tlsContext) {
        super(tlsContext);
    }
}
