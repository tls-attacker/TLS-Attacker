/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import static de.rub.nds.modifiablevariable.util.ArrayConverter.bytesToHexString;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PaddingExtensionMessage;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PaddingExtensionParser extends ExtensionParser<PaddingExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public PaddingExtensionParser(InputStream stream, Config config) {
        super(stream, config);
    }

    @Override
    public void parseExtensionMessageContent(PaddingExtensionMessage msg) {
        msg.setPaddingBytes(parseByteArrayField(getBytesLeft()));
        LOGGER
            .debug("The padding extension parser parsed the padding bytes " + bytesToHexString(msg.getPaddingBytes()));
    }
}
