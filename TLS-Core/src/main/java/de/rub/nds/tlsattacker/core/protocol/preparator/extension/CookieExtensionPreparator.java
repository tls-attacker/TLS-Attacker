/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.protocol.message.extension.CookieExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ExtensionSerializer;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 */
public class CookieExtensionPreparator extends ExtensionPreparator<CookieExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final CookieExtensionMessage msg;

    public CookieExtensionPreparator(Chooser chooser, CookieExtensionMessage message,
        ExtensionSerializer<CookieExtensionMessage> serializer) {
        super(chooser, message, serializer);
        this.msg = message;
    }

    @Override
    public void prepareExtensionContent() {
        LOGGER.debug("Preparing CookieExtensionMessage");
        msg.setCookie(chooser.getExtensionCookie());
        LOGGER.debug("Cookie: " + ArrayConverter.bytesToHexString(msg.getCookie().getValue()));
        msg.setCookieLength(chooser.getExtensionCookie().length);
        LOGGER.debug("Cookie length: " + msg.getCookieLength().getValue());
    }

}
