/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */

package de.rub.nds.tlsattacker.core.protocol.message.extension;

import de.rub.nds.tlsattacker.core.constants.ExtensionType;

/**
 * RFC7366
 */
public class EncryptThenMacExtensionMessage extends ExtensionMessage {

    public EncryptThenMacExtensionMessage() {
        super(ExtensionType.ENCRYPT_THEN_MAC);
    }

}
