/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.message;

import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.protocol.handler.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.tls.protocol.handler.HelloRequestHandler;
import de.rub.nds.tlsattacker.tls.protocol.serializer.Serializer;
import de.rub.nds.tlsattacker.tls.workflow.TlsConfig;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;

/**
 * @author Philip Riese <philip.riese@rub.de>
 */
public class HelloRequestMessage extends HandshakeMessage {

    public HelloRequestMessage(TlsConfig tlsConfig) {
        super(tlsConfig, HandshakeMessageType.HELLO_REQUEST);
        setIncludeInDigest(false);
    }

    public HelloRequestMessage() {
        super(HandshakeMessageType.HELLO_REQUEST);
        setIncludeInDigest(false);
    }
}
