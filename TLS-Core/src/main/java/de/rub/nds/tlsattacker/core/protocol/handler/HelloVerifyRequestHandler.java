/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.protocol.message.HelloVerifyRequestMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class HelloVerifyRequestHandler extends HandshakeMessageHandler<HelloVerifyRequestMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public HelloVerifyRequestHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public void adjustContext(HelloVerifyRequestMessage message) {
        adjustDTLSCookie(message);
    }

    private void adjustDTLSCookie(HelloVerifyRequestMessage message) {
        byte[] dtlsCookie = message.getCookie().getValue();
        context.setDtlsCookie(dtlsCookie);
        LOGGER.debug("Set DTLS Cookie in Context to " + ArrayConverter.bytesToHexString(dtlsCookie, false));
        context.getDigest().reset();
        LOGGER.debug("Resetting MessageDigest");
    }
}
