/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import static de.rub.nds.modifiablevariable.util.ArrayConverter.bytesToHexString;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PaddingExtensionMessage;

/**
 *
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
public class PaddingExtensionParser extends ExtensionParser<PaddingExtensionMessage> {

    public PaddingExtensionParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public void parseExtensionMessageContent(PaddingExtensionMessage msg) {
        if (msg.getExtensionLength().getValue() <= 65535) {
            LOGGER.warn("The Padding Extension length value exceeds the two bytes defined in RFC 7685.");
        }
        msg.setPaddingBytes(parseByteArrayField(msg.getExtensionLength().getValue()));
        LOGGER.debug("The padding extension parser parsed the padding bytes " + bytesToHexString(msg.getPaddingBytes()));
    }

    @Override
    protected PaddingExtensionMessage createExtensionMessage() {
        return new PaddingExtensionMessage();
    }

}
