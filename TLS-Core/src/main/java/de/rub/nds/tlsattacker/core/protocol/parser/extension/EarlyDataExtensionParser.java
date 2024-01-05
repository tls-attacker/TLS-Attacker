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
import de.rub.nds.tlsattacker.core.protocol.message.extension.EarlyDataExtensionMessage;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/** RFC draft-ietf-tls-tls13-21 */
public class EarlyDataExtensionParser extends ExtensionParser<EarlyDataExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public EarlyDataExtensionParser(InputStream stream, TlsContext tlsContext) {
        super(stream, tlsContext);
    }

    @Override
    public void parse(EarlyDataExtensionMessage msg) {
        LOGGER.debug("Parsing EarlyDataExtensionMessage");
        if (getTlsContext().getTalkingConnectionEndType() == ConnectionEndType.CLIENT) {
            parseMaxEarlyDataSize(msg);
        }
    }

    private void parseMaxEarlyDataSize(EarlyDataExtensionMessage msg) {
        msg.setMaxEarlyDataSize(parseIntField(ExtensionByteLength.MAX_EARLY_DATA_SIZE_LENGTH));
        LOGGER.debug("MaxEarlyDataSize: " + msg.getMaxEarlyDataSize().getValue());
    }
}
