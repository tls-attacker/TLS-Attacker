/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.parser.extension;

import de.rub.nds.tlsattacker.tls.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.tls.protocol.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.tls.protocol.extension.UnknownExtensionMessage;
import de.rub.nds.tlsattacker.tls.protocol.parser.Parser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 * @param <T>
 */
public abstract class ExtensionParser<T extends ExtensionMessage> extends Parser<T> {

    private static final Logger LOGGER = LogManager.getLogger("PARSER");

    public ExtensionParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    /**
     * Reads the next bytes as the length of the Extension and writes them in
     * the message
     *
     * @param message
     *            Message to write in
     */
    protected void parseExtensionLength(UnknownExtensionMessage message) {
        message.setExtensionLength(parseIntField(ExtensionByteLength.EXTENSIONS_LENGTH));
    }

    /**
     * Reads the next bytes as the type of the Extension and writes it in the
     * message
     *
     * @param message
     *            Message to write in
     */
    protected void parseExtensionType(UnknownExtensionMessage message) {
        message.setExtensionType(parseByteArrayField(ExtensionByteLength.TYPE));
    }

    /**
     * Checks if the Extension has ExtensionData specified
     *
     * @param message
     *            The message to check
     * @return True if extension did specify Data in its length field
     */
    protected boolean hasExtensionData(UnknownExtensionMessage message) {
        return message.getExtensionLength().getValue() > 0;
    }

    protected void setExtensionBytes(UnknownExtensionMessage message) {
        message.setExtensionBytes(getAlreadyParsed());
    }

}
