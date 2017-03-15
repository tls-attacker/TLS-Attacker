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
import de.rub.nds.tlsattacker.tls.protocol.extension.MaxFragmentLengthExtensionMessage;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class MaxFragmentLengthExtensionParser extends ExtensionParser<MaxFragmentLengthExtensionMessage>{

    public MaxFragmentLengthExtensionParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public MaxFragmentLengthExtensionMessage parse() {
        MaxFragmentLengthExtensionMessage msg = new MaxFragmentLengthExtensionMessage();
        parseExtensionType(msg);
        parseExtensionLength(msg);
        msg.setMaxFragmentLength(parseByteArrayField(ExtensionByteLength.MAX_FRAGMENT_EXTENSION_LENGTH));
        return msg;
    }
    
}
