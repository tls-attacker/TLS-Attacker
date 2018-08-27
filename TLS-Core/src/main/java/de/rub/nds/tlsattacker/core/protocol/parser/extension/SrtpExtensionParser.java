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
import de.rub.nds.tlsattacker.core.protocol.message.extension.SrtpExtensionMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SrtpExtensionParser extends ExtensionParser<SrtpExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SrtpExtensionParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public void parseExtensionMessageContent(SrtpExtensionMessage msg) {
        msg.setSrtpProtectionProfilesLength(parseIntField(ExtensionByteLength.SRTP_PROTECTION_PROFILES_LENGTH));
        LOGGER.debug("Parsed the srtp protection profiles length of "
                + msg.getSrtpProtectionProfilesLength().getValue());
        msg.setSrtpProtectionProfiles(parseByteArrayField(msg.getSrtpProtectionProfilesLength().getValue()));
        LOGGER.debug("Parsed the srtp protection profiles "
                + ArrayConverter.bytesToHexString(msg.getSrtpProtectionProfiles()));
        msg.setSrtpMkiLength(parseIntField(ExtensionByteLength.SRTP_MASTER_KEY_IDENTIFIER_LENGTH));
        LOGGER.debug("Parsed the srtp mki length of " + msg.getSrtpMkiLength().getValue());
        if (msg.getSrtpMkiLength().getValue() != 0) {
            msg.setSrtpMki(parseByteArrayField(msg.getSrtpMkiLength().getValue()));
            LOGGER.debug("Parsed the srtp mki " + ArrayConverter.bytesToHexString(msg.getSrtpMki()));
        } else {
            LOGGER.debug("Parsed no srtp mki");
            msg.setSrtpMki(new byte[0]);
        }

    }

    @Override
    protected SrtpExtensionMessage createExtensionMessage() {
        return new SrtpExtensionMessage();
    }

}
