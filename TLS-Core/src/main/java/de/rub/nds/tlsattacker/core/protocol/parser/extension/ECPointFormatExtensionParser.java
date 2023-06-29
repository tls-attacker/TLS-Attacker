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
import de.rub.nds.tlsattacker.core.protocol.message.extension.ECPointFormatExtensionMessage;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ECPointFormatExtensionParser extends ExtensionParser<ECPointFormatExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ECPointFormatExtensionParser(InputStream stream, TlsContext tlsContext) {
        super(stream, tlsContext);
    }

    @Override
    public void parse(ECPointFormatExtensionMessage msg) {
        LOGGER.debug("Parsing ECPointFormatExtensionMessage");
        parsePointFormatsLength(msg);
        parsePointFormat(msg);
    }

    /**
     * Reads the next bytes as the PointFormatsLength of the Extension and writes them in the
     * message
     *
     * @param msg Message to write in
     */
    private void parsePointFormatsLength(ECPointFormatExtensionMessage msg) {
        msg.setPointFormatsLength(parseIntField(ExtensionByteLength.EC_POINT_FORMATS));
        LOGGER.debug("PointFormatsLength: " + msg.getPointFormatsLength().getValue());
    }

    /**
     * Reads the next bytes as the PointFormat of the Extension and writes them in the message
     *
     * @param msg Message to write in
     */
    private void parsePointFormat(ECPointFormatExtensionMessage msg) {
        msg.setPointFormats(parseByteArrayField(msg.getPointFormatsLength().getValue()));
        LOGGER.debug("PointFormats: {}", msg.getPointFormats().getValue());
    }
}
