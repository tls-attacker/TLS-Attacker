/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EncryptedClientHelloEncryptedExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.EchConfigParser;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.ExtensionParser;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class EncryptedClientHelloEncryptedExtensionParser
        extends ExtensionParser<EncryptedClientHelloEncryptedExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public EncryptedClientHelloEncryptedExtensionParser(InputStream stream, TlsContext tlsContext) {
        super(stream, tlsContext);
    }

    @Override
    public void parse(EncryptedClientHelloEncryptedExtensionMessage msg) {
        parseConfigsLength(msg);
        parseConfigs(msg);
    }

    private void parseConfigsLength(EncryptedClientHelloEncryptedExtensionMessage msg) {
        msg.setEchConfigsLength(this.parseIntField(ExtensionByteLength.ECH_CONFIG_LIST_LENGTH));
        LOGGER.debug("Configs Length: {}", msg.getEchConfigsLength());
    }

    private void parseConfigs(EncryptedClientHelloEncryptedExtensionMessage msg) {
        EchConfigParser parser = new EchConfigParser(getStream(), getTlsContext());
        parser.parse(msg.getEchConfigs(), msg.getEchConfigsLength().getValue());
    }
}
