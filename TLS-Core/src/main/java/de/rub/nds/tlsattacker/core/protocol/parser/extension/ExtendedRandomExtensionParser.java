/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtendedRandomExtensionMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import static de.rub.nds.modifiablevariable.util.ArrayConverter.bytesToHexString;

/**
 * This classes handles the parsing of the Extended Random Extensions as defined
 * as in https://tools.ietf.org/html/draft-rescorla-tls-extended-random-02
 */
public class ExtendedRandomExtensionParser extends ExtensionParser<ExtendedRandomExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ExtendedRandomExtensionParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public void parseExtensionMessageContent(ExtendedRandomExtensionMessage msg) {
        if (msg.getExtensionLength().getValue() > 65535) {
            LOGGER.warn("The extended Random length shouldn't exceed 2 bytes as defined in Extended Random Draft. "
                    + "Length was " + msg.getExtensionLength().getValue());
        }

        msg.setExtendedRandom(parseByteArrayField(msg.getExtensionLength().getValue()));
        LOGGER.debug("The extended Random TLS parser parsed the value " + bytesToHexString(msg.getExtendedRandom()));
    }

    @Override
    protected ExtendedRandomExtensionMessage createExtensionMessage() {
        return new ExtendedRandomExtensionMessage();
    }

}
