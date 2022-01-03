/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.extension.CookieExtensionMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class CookieExtensionParser extends ExtensionParser<CookieExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public CookieExtensionParser(int startposition, byte[] array, Config config) {
        super(startposition, array, config);
    }

    @Override
    public void parseExtensionMessageContent(CookieExtensionMessage msg) {
        LOGGER.debug("Parsing CookieExtensionMessage");
        parseCookieLength(msg);
        parseCookie(msg);
    }

    private void parseCookieLength(CookieExtensionMessage msg) {
        msg.setCookieLength(parseIntField(ExtensionByteLength.COOKIE_LENGTH));
        LOGGER.debug("Cookie length: " + msg.getCookieLength().getValue());
    }

    private void parseCookie(CookieExtensionMessage msg) {
        msg.setCookie(parseByteArrayField(msg.getCookieLength().getValue()));
        LOGGER.debug("Cookie: " + ArrayConverter.bytesToHexString(msg.getCookie().getValue()));
    }

    @Override
    protected CookieExtensionMessage createExtensionMessage() {
        return new CookieExtensionMessage();
    }

}
