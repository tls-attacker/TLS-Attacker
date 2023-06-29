/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessageParser;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.ExtensionListParser;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * An abstract Parser class for HandshakeMessages
 *
 * @param <T> Type of the HandshakeMessages to parse
 */
public abstract class HandshakeMessageParser<T extends HandshakeMessage>
        extends ProtocolMessageParser<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    /** The expected value for the Type field of the Message */
    private ProtocolVersion version;

    private TlsContext tlsContext;

    /**
     * Constructor for the Parser class
     *
     * @param stream
     * @param version The Version with which this message should be parsed
     * @param tlsContext
     */
    public HandshakeMessageParser(
            InputStream stream, ProtocolVersion version, TlsContext tlsContext) {
        super(stream);
        this.version = version;
        this.tlsContext = tlsContext;
    }

    /**
     * Constructor for the Parser class
     *
     * @param stream
     * @param tlsContext
     */
    public HandshakeMessageParser(InputStream stream, TlsContext tlsContext) {
        this(
                stream,
                (tlsContext.getSelectedProtocolVersion() != null
                        ? tlsContext.getSelectedProtocolVersion()
                        : tlsContext.getChooser().getLastRecordVersion()),
                tlsContext);
    }

    /**
     * Reads the next bytes as the ExtensionLength and writes them in the message
     *
     * @param message Message to write in
     */
    protected void parseExtensionLength(T message) {
        message.setExtensionsLength(parseIntField(HandshakeByteLength.EXTENSION_LENGTH));
        LOGGER.debug("ExtensionLength:" + message.getExtensionsLength().getValue());
    }

    /**
     * Reads the next bytes as the ExtensionBytes and writes them in the message and adds parsed
     * Extensions to the message
     *
     * @param message Message to write in
     * @param helloRetryRequestHint
     */
    protected void parseExtensionBytes(T message, boolean helloRetryRequestHint) {
        byte[] extensionBytes = parseByteArrayField(message.getExtensionsLength().getValue());
        message.setExtensionBytes(extensionBytes);
        LOGGER.debug("ExtensionBytes:{}", extensionBytes);

        ByteArrayInputStream innerStream = new ByteArrayInputStream(extensionBytes);
        ExtensionListParser parser =
                new ExtensionListParser(innerStream, tlsContext, helloRetryRequestHint);
        List<ExtensionMessage> extensionMessages = new LinkedList<>();
        parser.parse(extensionMessages);
        message.setExtensions(extensionMessages);
    }

    /**
     * Checks if the message has an ExtensionLength field, by checking if there are more bytes in
     * the inputstream
     *
     * @return True if the message has an Extension field
     */
    protected boolean hasExtensionLengthField() {
        return getBytesLeft() > 0;
    }

    /**
     * Checks if the ExtensionsLengthField has a value greater than Zero, eg. if there are
     * Extensions present.
     *
     * @param message Message to check
     * @return True if the message has Extensions
     */
    protected boolean hasExtensions(T message) {
        return message.getExtensionsLength().getValue() > 0;
    }

    protected ProtocolVersion getVersion() {
        return version;
    }

    protected void setVersion(ProtocolVersion version) {
        this.version = version;
    }
}
