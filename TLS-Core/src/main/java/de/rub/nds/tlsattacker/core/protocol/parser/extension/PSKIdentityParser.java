/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.layer.data.Parser;
import de.rub.nds.tlsattacker.core.protocol.message.extension.psk.PSKIdentity;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PSKIdentityParser extends Parser<PSKIdentity> {

    private static final Logger LOGGER = LogManager.getLogger();

    public PSKIdentityParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parse(PSKIdentity pskIdentity) {
        LOGGER.debug("Parsing PSKIdentity");
        parseIdentityLength(pskIdentity);
        parseIdentity(pskIdentity);
        parseObfuscatedTicketAge(pskIdentity);
    }

    private void parseIdentityLength(PSKIdentity pskIdentity) {
        pskIdentity.setIdentityLength(parseIntField(ExtensionByteLength.PSK_IDENTITY_LENGTH));
        LOGGER.debug("Identity length:" + pskIdentity.getIdentityLength().getValue());
    }

    private void parseIdentity(PSKIdentity pskIdentity) {
        pskIdentity.setIdentity(parseByteArrayField(pskIdentity.getIdentityLength().getValue()));
        LOGGER.debug("Identity: {}", pskIdentity.getIdentity().getValue());
    }

    private void parseObfuscatedTicketAge(PSKIdentity pskIdentity) {
        pskIdentity.setObfuscatedTicketAge(
                parseByteArrayField(ExtensionByteLength.TICKET_AGE_LENGTH));
        LOGGER.debug("Obfuscated ticket age: {}", pskIdentity.getObfuscatedTicketAge().getValue());
    }
}
