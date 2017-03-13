/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.preparator;

import de.rub.nds.tlsattacker.tls.protocol.message.HelloVerifyRequestMessage;
import de.rub.nds.tlsattacker.tls.protocol.parser.*;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.util.RandomHelper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class HelloVerifyRequestPreparator extends HandshakeMessagePreparator<HelloVerifyRequestMessage> {

    private static final Logger LOGGER = LogManager.getLogger("PREPARATOR");

    private final HelloVerifyRequestMessage message;

    public HelloVerifyRequestPreparator(TlsContext context, HelloVerifyRequestMessage message) {
        super(context, message);
        this.message = message;
    }

    @Override
    public void prepareHandshakeMessageContents() {
        message.setCookie(generateCookie());
        message.setCookieLength((byte) message.getCookie().getValue().length);// TODO
                                                                              // WARN
        message.setProtocolVersion(context.getConfig().getHighestProtocolVersion().getValue());
    }

    private byte[] generateCookie() {
        byte[] cookie = new byte[context.getConfig().getDTLSCookieLength()];
        RandomHelper.getRandom().nextBytes(cookie);
        return cookie;
    }

}
