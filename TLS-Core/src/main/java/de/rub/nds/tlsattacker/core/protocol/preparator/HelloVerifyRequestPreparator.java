/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.tlsattacker.core.protocol.message.HelloVerifyRequestMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class HelloVerifyRequestPreparator
        extends HandshakeMessagePreparator<HelloVerifyRequestMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final HelloVerifyRequestMessage msg;

    public HelloVerifyRequestPreparator(Chooser chooser, HelloVerifyRequestMessage message) {
        super(chooser, message);
        this.msg = message;
    }

    @Override
    public void prepareHandshakeMessageContents() {
        LOGGER.debug("Preparing HelloVerifyRequestMessage");
        prepareCookie(msg);
        prepareCookieLength(msg);
        // WARN
        prepareProtocolVersion(msg);
    }

    private byte[] generateCookie() {
        int cookieLength = chooser.getConfig().getDtlsDefaultCookieLength();
        if (cookieLength > 256) {
            LOGGER.warn("Cookie length is greater than 256. Returning it mod 256");
            cookieLength = cookieLength % 256;
        }
        byte[] cookie = new byte[cookieLength];
        chooser.getContext().getTlsContext().getRandom().nextBytes(cookie);
        return cookie;
    }

    private void prepareCookie(HelloVerifyRequestMessage msg) {
        msg.setCookie(generateCookie());
        LOGGER.debug("Cookie: {}", msg.getCookie().getValue());
    }

    private void prepareCookieLength(HelloVerifyRequestMessage msg) {
        msg.setCookieLength((byte) msg.getCookie().getValue().length); // TODO
        LOGGER.debug("CookieLength: " + msg.getCookieLength().getValue());
    }

    private void prepareProtocolVersion(HelloVerifyRequestMessage msg) {
        msg.setProtocolVersion(chooser.getConfig().getHighestProtocolVersion().getValue());
        LOGGER.debug("ProtocolVersion: {}", msg.getProtocolVersion().getValue());
    }
}
