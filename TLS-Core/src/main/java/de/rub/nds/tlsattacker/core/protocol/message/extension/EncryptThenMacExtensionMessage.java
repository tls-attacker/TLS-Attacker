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
 * RFC7366
 */
@XmlRootElement(name = "EncryptThenMacExtension")
public class EncryptThenMacExtensionMessage extends ExtensionMessage {

    public EncryptThenMacExtensionMessage() {
        super(ExtensionType.ENCRYPT_THEN_MAC);
    }

    public EncryptThenMacExtensionMessage(Config configF) {
        super(ExtensionType.ENCRYPT_THEN_MAC);
    }

}
