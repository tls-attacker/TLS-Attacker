/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import static de.rub.nds.modifiablevariable.util.ArrayConverter.bytesToHexString;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtendedRandomExtensionMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * This classes handles the parsing of the Extended Random Extensions as defined as in
 * https://tools.ietf.org/html/draft-rescorla-tls-extended-random-02
 */
public class ExtendedRandomExtensionParser extends ExtensionParser<ExtendedRandomExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ExtendedRandomExtensionParser(int startposition, byte[] array, Config config) {
        super(startposition, array, config);
    }

    @Override
    public void parseExtensionMessageContent(ExtendedRandomExtensionMessage msg) {
        parseExtendedRandomLength(msg);
        msg.setExtendedRandom(parseByteArrayField(msg.getExtendedRandomLength().getValue()));
        LOGGER.debug("The extended Random TLS parser parsed the value " + bytesToHexString(msg.getExtendedRandom()));
    }

    private void parseExtendedRandomLength(ExtendedRandomExtensionMessage msg) {
        msg.setExtendedRandomLength(parseIntField(ExtensionByteLength.EXTENDED_RANDOM_LENGTH));
        LOGGER.debug("ExtendedRandomLength : " + msg.getExtendedRandomLength().getValue());
    }

    @Override
    protected ExtendedRandomExtensionMessage createExtensionMessage() {
        return new ExtendedRandomExtensionMessage();
    }

}
