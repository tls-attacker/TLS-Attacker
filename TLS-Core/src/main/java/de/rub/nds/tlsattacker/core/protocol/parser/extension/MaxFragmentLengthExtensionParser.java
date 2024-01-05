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
import de.rub.nds.tlsattacker.core.protocol.message.extension.MaxFragmentLengthExtensionMessage;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class MaxFragmentLengthExtensionParser
        extends ExtensionParser<MaxFragmentLengthExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public MaxFragmentLengthExtensionParser(InputStream stream, TlsContext tlsContext) {
        super(stream, tlsContext);
    }

    @Override
    public void parse(MaxFragmentLengthExtensionMessage msg) {
        LOGGER.debug("Parsing MaxFragmentLengthExtensionMessage");
        parseMaxFragmentLength(msg);
    }

    /**
     * Reads the next bytes as the maxFragmentLength of the Extension and writes them in the message
     *
     * @param msg Message to write in
     */
    private void parseMaxFragmentLength(MaxFragmentLengthExtensionMessage msg) {
        msg.setMaxFragmentLength(parseByteArrayField(ExtensionByteLength.MAX_FRAGMENT));
        LOGGER.debug("MaxFragmentLength: {}", msg.getMaxFragmentLength().getValue());
    }
}
