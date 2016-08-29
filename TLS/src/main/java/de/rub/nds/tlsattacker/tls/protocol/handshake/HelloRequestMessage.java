/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.handshake;

import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;

/**
 * @author Philip Riese <philip.riese@rub.de>
 */
public class HelloRequestMessage extends HandshakeMessage {

    public HelloRequestMessage() {
	super(HandshakeMessageType.HELLO_REQUEST);
	setIncludeInDigest(false);
    }
}
