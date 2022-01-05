/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.message.extension;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import javax.xml.bind.annotation.XmlRootElement;

/**
 * This is a binary extension, which means that no extension data is used. This extension is defined in RFC6066
 */
@XmlRootElement(name = "TruncatedHmacExtension")
public class TruncatedHmacExtensionMessage extends ExtensionMessage {

    public TruncatedHmacExtensionMessage() {
        super(ExtensionType.TRUNCATED_HMAC);
    }

    public TruncatedHmacExtensionMessage(Config config) {
        super(ExtensionType.TRUNCATED_HMAC);
    }
}
