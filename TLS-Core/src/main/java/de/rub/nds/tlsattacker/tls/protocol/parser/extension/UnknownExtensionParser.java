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
import de.rub.nds.tlsattacker.tls.protocol.extension.UnknownExtensionMessage;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class UnknownExtensionParser extends ExtensionParser<UnknownExtensionMessage> {

    public UnknownExtensionParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public UnknownExtensionMessage parse() {
        UnknownExtensionMessage message = new UnknownExtensionMessage();
        // It might be that there is not enoguth data left to parse a proper but
        // unknown extension
        // in that case we just add the remaining bytes into the unknown
        // extension and warn the user
        if (enoughBytesLeft(ExtensionByteLength.TYPE + ExtensionByteLength.EXTENSIONS_LENGTH)) {
            parseExtensionType(message);
            parseExtensionLength(message);
            if (hasExtensionData(message)) {
                parseExtensionData(message);
            }

        } else {
            parseByteArrayField(getBytesLeft());
        }
        setExtensionBytes(message);
        return message;
    }

    /**
     * Reads the next bytes as extension Bytes and writes it in the message. If
     * the extension did specify more bytes than there are left according to the
     * ExtensionLength field of the carrier Message. The carrier length field is
     * respected and just the remaining bytes are parsed
     *
     * @param message
     *            Message to write in
     */
    protected void parseExtensionData(UnknownExtensionMessage message) {
        if (getBytesLeft() == 0) {
            // No bytes left for extension data
        } else if (getBytesLeft() < message.getExtensionLength().getValue()) {
            message.setExtensionData(parseByteArrayField(getBytesLeft()));
        } else {
            message.setExtensionData(parseByteArrayField(message.getExtensionLength().getValue()));
        }
    }
}
