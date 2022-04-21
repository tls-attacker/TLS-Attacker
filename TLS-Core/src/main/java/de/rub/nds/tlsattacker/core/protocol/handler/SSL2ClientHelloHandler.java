/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.SSL2ClientHelloMessage;

public class SSL2ClientHelloHandler extends HandshakeMessageHandler<SSL2ClientHelloMessage> {

    public SSL2ClientHelloHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public void adjustContext(SSL2ClientHelloMessage message) {
        tlsContext.setClientRandom(message.getChallenge().getValue());
    }

}
