/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.protocol.message.HelloVerifyRequestMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class HelloVerifyRequestPreparator extends HandshakeMessagePreparator<HelloVerifyRequestMessage> {

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
        byte[] cookie = new byte[chooser.getConfig().getDtlsDefaultCookieLength()];
        chooser.getContext().getRandom().nextBytes(cookie);
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
        msg.setProtocolVersion(chooser.getConfig().getHighestProtocolVersion().getValue());
        LOGGER.debug("ProtocolVersion: " + ArrayConverter.bytesToHexString(msg.getProtocolVersion().getValue()));
    }

}
