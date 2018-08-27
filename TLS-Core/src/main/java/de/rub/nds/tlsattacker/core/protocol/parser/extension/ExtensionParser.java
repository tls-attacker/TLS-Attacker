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
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.Parser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * @param <T>
 *            The ExtensionMessage that should be parsed
 */
public abstract class ExtensionParser<T extends ExtensionMessage> extends Parser<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ExtensionParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public final T parse() {
        LOGGER.debug("Parsing ExtensionMessage");
        T msg = createExtensionMessage();
        parseExtensionType(msg);
        parseExtensionLength(msg);
        parseExtensionMessageContent(msg);
        setExtensionBytes(msg);
        return msg;
    }

    public abstract void parseExtensionMessageContent(T msg);

    protected abstract T createExtensionMessage();

    /**
     * Reads the next bytes as the length of the Extension and writes them in
     * the message
     *
     * @param msg
     *            Message to write in
     */
    private void parseExtensionLength(ExtensionMessage msg) {
        msg.setExtensionLength(parseIntField(ExtensionByteLength.EXTENSIONS_LENGTH));
        LOGGER.debug("ExtensionLength: " + msg.getExtensionLength().getValue());
    }

    /**
     * Reads the next bytes as the type of the Extension and writes it in the
     * message
     *
     * @param msg
     *            Message to write in
     */
    private void parseExtensionType(ExtensionMessage msg) {
        msg.setExtensionType(parseByteArrayField(ExtensionByteLength.TYPE));
        LOGGER.debug("ExtensionType: " + ArrayConverter.bytesToHexString(msg.getExtensionType().getValue()));
    }

    /**
     * Checks if the Extension has ExtensionData specified
     *
     * @param message
     *            The message to check
     * @return True if extension did specify Data in its length field
     */
    protected boolean hasExtensionData(ExtensionMessage message) {
        return message.getExtensionLength().getValue() > 0;
    }

    protected void setExtensionBytes(ExtensionMessage msg) {
        msg.setExtensionBytes(getAlreadyParsed());
        LOGGER.debug("ExtensionBytes: " + ArrayConverter.bytesToHexString(msg.getExtensionBytes().getValue()));
    }

}
