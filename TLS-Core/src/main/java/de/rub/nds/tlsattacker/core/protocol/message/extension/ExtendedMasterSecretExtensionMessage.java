/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.message.extension;

import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.ExtendedMasterSecretExtensionHandler;
import de.rub.nds.tlsattacker.core.state.TlsContext;

/**
 * This is the extended_master_secret message. There is no need for any data,
 * the presence of this extension is enough.
 *
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
public class ExtendedMasterSecretExtensionMessage extends ExtensionMessage {

    public ExtendedMasterSecretExtensionMessage() {
        super(ExtensionType.EXTENDED_MASTER_SECRET);
    }

    @Override
    public ExtendedMasterSecretExtensionHandler getHandler(TlsContext context) {
        return new ExtendedMasterSecretExtensionHandler(context);
    }

}
