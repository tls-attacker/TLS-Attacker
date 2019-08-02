/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.extension.psk.PSKIdentity;
import de.rub.nds.tlsattacker.core.protocol.parser.Parser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PSKIdentityParser extends Parser<PSKIdentity> {

    private static final Logger LOGGER = LogManager.getLogger();

    public PSKIdentityParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public PSKIdentity parse() {
        LOGGER.debug("Parsing PSKIdentity");
        PSKIdentity pskIdentity = new PSKIdentity();
        parseIdentityLength(pskIdentity);
        parseIdentity(pskIdentity);
        parseObfuscatedTicketAge(pskIdentity);
        return pskIdentity;
    }

    private void parseIdentityLength(PSKIdentity pskIdentity) {
        pskIdentity.setIdentityLength(parseIntField(ExtensionByteLength.PSK_IDENTITY_LENGTH));
        LOGGER.debug("Identity length:" + pskIdentity.getIdentityLength().getValue());
    }

    private void parseIdentity(PSKIdentity pskIdentity) {
        pskIdentity.setIdentity(parseByteArrayField(pskIdentity.getIdentityLength().getValue()));
        LOGGER.debug("Identity:" + ArrayConverter.bytesToHexString(pskIdentity.getIdentity().getValue()));
    }

    private void parseObfuscatedTicketAge(PSKIdentity pskIdentity) {
        pskIdentity.setObfuscatedTicketAge(parseByteArrayField(ExtensionByteLength.TICKET_AGE_LENGTH));
        LOGGER.debug("Obfuscated ticket age:"
                + ArrayConverter.bytesToHexString(pskIdentity.getObfuscatedTicketAge().getValue()));
    }

}
