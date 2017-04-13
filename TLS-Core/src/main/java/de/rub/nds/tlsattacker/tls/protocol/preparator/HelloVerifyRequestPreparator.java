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
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.modifiablevariable.util.RandomHelper;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class HelloVerifyRequestPreparator extends HandshakeMessagePreparator<HelloVerifyRequestMessage> {

    private final HelloVerifyRequestMessage msg;

    public HelloVerifyRequestPreparator(TlsContext context, HelloVerifyRequestMessage message) {
        super(context, message);
        this.msg = message;
    }

    @Override
    public void prepareHandshakeMessageContents() {
        prepareCookie(msg);
        prepareCookieLength(msg);
        // WARN
        prepareProtocolVersion(msg);
    }

    private byte[] generateCookie() {
        byte[] cookie = new byte[context.getConfig().getDefaultDTLSCookieLength()];
        RandomHelper.getRandom().nextBytes(cookie);
        return cookie;
    }

    private void prepareCookie(HelloVerifyRequestMessage msg) {
        msg.setCookie(generateCookie());
        LOGGER.debug("Cookie: " + ArrayConverter.bytesToHexString(msg.getCookie().getValue()));
    }

    private void prepareCookieLength(HelloVerifyRequestMessage msg) {
        msg.setCookieLength((byte) msg.getCookie().getValue().length);// TODO
        LOGGER.debug("CookieLength: " + msg.getCookieLength().getValue());
    }

    private void prepareProtocolVersion(HelloVerifyRequestMessage msg) {
        msg.setProtocolVersion(context.getConfig().getHighestProtocolVersion().getValue());
        LOGGER.debug("ProtocolVersion: " + ArrayConverter.bytesToHexString(msg.getProtocolVersion().getValue()));
    }

}
