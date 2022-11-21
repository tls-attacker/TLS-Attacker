/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.Parser;
import de.rub.nds.tlsattacker.core.protocol.parser.context.MessageParserBoundaryVerificationContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * @param <T>
 *            The ExtensionMessage that should be parsed
 */
public abstract class ExtensionParser<T extends ExtensionMessage> extends Parser<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final Config config;

    public ExtensionParser(int startposition, byte[] array, Config config) {
        super(startposition, array);
        this.config = config;
    }

    @Override
    public final T parse() {
        LOGGER.debug("Parsing ExtensionMessage");
        T msg = createExtensionMessage();
        parseExtensionType(msg);
        parseExtensionLength(msg);
        pushContext(new MessageParserBoundaryVerificationContext(msg.getExtensionLength().getValue(),
            String.format("Extension Length [%s]", msg.getExtensionTypeConstant()), getPointer(),
            config.isThrowExceptionOnParserContextViolation()));
        parseExtensionMessageContent(msg);
        popContext();
        setExtensionBytes(msg);
        return msg;
    }

    public abstract void parseExtensionMessageContent(T msg);

    protected abstract T createExtensionMessage();

    /**
     * Reads the next bytes as the length of the Extension and writes them in the message
     *
     * @param msg
     *            Message to write in
     */
    private void parseExtensionLength(ExtensionMessage msg) {
        msg.setExtensionLength(parseIntField(ExtensionByteLength.EXTENSIONS_LENGTH));
        LOGGER.debug("ExtensionLength: " + msg.getExtensionLength().getValue());
    }

    /**
     * Reads the next bytes as the type of the Extension and writes it in the message
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
     * @param  message
     *                 The message to check
     * @return         True if extension did specify Data in its length field
     */
    protected boolean hasExtensionData(ExtensionMessage message) {
        return message.getExtensionLength().getValue() > 0;
    }

    protected void setExtensionBytes(ExtensionMessage msg) {
        msg.setExtensionBytes(getAlreadyParsed());
        LOGGER.debug("ExtensionBytes: " + ArrayConverter.bytesToHexString(msg.getExtensionBytes().getValue()));
    }

}
