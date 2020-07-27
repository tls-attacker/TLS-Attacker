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

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;

public class DraftKeyShareExtensionMessage extends KeyShareExtensionMessage {

    public DraftKeyShareExtensionMessage() {
        super();
        extensionTypeConstant = ExtensionType.KEY_SHARE_OLD;
    }

    public DraftKeyShareExtensionMessage(Config tlsConfig) {
        super(tlsConfig);
        extensionTypeConstant = ExtensionType.KEY_SHARE_OLD;
    }

}
