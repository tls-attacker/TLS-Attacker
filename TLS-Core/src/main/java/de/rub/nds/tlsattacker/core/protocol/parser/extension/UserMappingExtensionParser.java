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
import de.rub.nds.tlsattacker.core.protocol.message.extension.UserMappingExtensionMessage;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class UserMappingExtensionParser extends ExtensionParser<UserMappingExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public UserMappingExtensionParser(InputStream stream, TlsContext tlsContext) {
        super(stream, tlsContext);
    }

    @Override
    public void parse(UserMappingExtensionMessage msg) {
        msg.setUserMappingType(parseByteField(ExtensionByteLength.USER_MAPPING_MAPPINGTYPE));
        LOGGER.debug(
                "Parsed the user mapping extension with mapping hint type "
                        + msg.getUserMappingType().getValue());
    }
}
