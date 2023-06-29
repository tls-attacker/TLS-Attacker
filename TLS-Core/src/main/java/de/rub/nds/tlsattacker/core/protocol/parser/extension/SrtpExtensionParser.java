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
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SrtpExtensionMessage;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SrtpExtensionParser extends ExtensionParser<SrtpExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SrtpExtensionParser(InputStream stream, TlsContext tlsContext) {
        super(stream, tlsContext);
    }

    @Override
    public void parse(SrtpExtensionMessage msg) {
        msg.setSrtpProtectionProfilesLength(
                parseIntField(ExtensionByteLength.SRTP_PROTECTION_PROFILES_LENGTH));
        LOGGER.debug(
                "Parsed the srtp protection profiles length of "
                        + msg.getSrtpProtectionProfilesLength().getValue());
        msg.setSrtpProtectionProfiles(
                parseByteArrayField(msg.getSrtpProtectionProfilesLength().getValue()));
        LOGGER.debug("Parsed the srtp protection profiles {}", msg.getSrtpProtectionProfiles());
        msg.setSrtpMkiLength(parseIntField(ExtensionByteLength.SRTP_MASTER_KEY_IDENTIFIER_LENGTH));
        LOGGER.debug("Parsed the srtp mki length of " + msg.getSrtpMkiLength().getValue());
        msg.setSrtpMki(parseByteArrayField(msg.getSrtpMkiLength().getValue()));
        LOGGER.debug("Parsed the srtp mki {}", msg.getSrtpMki());
    }
}
