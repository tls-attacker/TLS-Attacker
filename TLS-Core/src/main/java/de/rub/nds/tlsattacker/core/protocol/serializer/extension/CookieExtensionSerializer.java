/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.extension.CookieExtensionMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class CookieExtensionSerializer extends ExtensionSerializer<CookieExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final CookieExtensionMessage msg;

    public CookieExtensionSerializer(CookieExtensionMessage message) {
        super(message);
        this.msg = message;
    }

    @Override
    public byte[] serializeExtensionContent() {
        LOGGER.debug("Serializing CookieExtensionMessage");
        serializeCookieLength(msg);
        serializeCookie(msg);
        return getAlreadySerialized();
    }

    private void serializeCookieLength(CookieExtensionMessage msg) {
        appendInt(msg.getCookieLength().getValue(), ExtensionByteLength.COOKIE_LENGTH);
        LOGGER.debug("Cookie length: " + msg.getCookieLength().getValue());
    }

    private void serializeCookie(CookieExtensionMessage msg) {
        appendBytes(msg.getCookie().getValue());
        LOGGER.debug("Cookie: " + ArrayConverter.bytesToHexString(msg.getCookie().getValue()));
    }

}
