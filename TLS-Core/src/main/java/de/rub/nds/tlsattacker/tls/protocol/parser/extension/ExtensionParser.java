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
import de.rub.nds.tlsattacker.tls.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.extension.UnknownExtensionMessage;
import de.rub.nds.tlsattacker.tls.protocol.parser.Parser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 * @param <T>
 */
public abstract class ExtensionParser<T extends ExtensionMessage> extends Parser<T> {

    public ExtensionParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public final T parse() {
        T msg = createExtensionMessage();
        parseExtensionType(msg);
        parseExtensionLength(msg);
        parseExtensionMessageContent(msg);
        msg.setExtensionBytes(getAlreadyParsed());
        return msg;
    }

    public abstract void parseExtensionMessageContent(T msg);

    protected abstract T createExtensionMessage();

    /**
     * Reads the next bytes as the length of the Extension and writes them in
     * the message
     *
     * @param message
     *            Message to write in
     */
    private void parseExtensionLength(ExtensionMessage message) {
        message.setExtensionLength(parseIntField(ExtensionByteLength.EXTENSIONS_LENGTH));
    }

    /**
     * Reads the next bytes as the type of the Extension and writes it in the
     * message
     *
     * @param message
     *            Message to write in
     */
    private void parseExtensionType(ExtensionMessage message) {
        message.setExtensionType(parseByteArrayField(ExtensionByteLength.TYPE));
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

    protected void setExtensionBytes(ExtensionMessage message) {
        message.setExtensionBytes(getAlreadyParsed());
    }

}
