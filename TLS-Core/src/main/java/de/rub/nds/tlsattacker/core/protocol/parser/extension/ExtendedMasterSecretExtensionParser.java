/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtendedMasterSecretExtensionMessage;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ExtendedMasterSecretExtensionParser extends ExtensionParser<ExtendedMasterSecretExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ExtendedMasterSecretExtensionParser(InputStream stream) {
        super(stream);
    }

    /**
     * Parses the content of the extended master secret extension message. There SHOULDN'T be any data.
     *
     * @param msg
     *            The Message that should be parsed
     */
    @Override
    public void parseExtensionMessageContent(ExtendedMasterSecretExtensionMessage msg) {
    }

}
