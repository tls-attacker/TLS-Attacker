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
import de.rub.nds.tlsattacker.core.protocol.handler.extension.TruncatedHmacExtensionHandler;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;

/**
 * This is a binary extension, which means that no extension data is used. This
 * extension is defined in RFC6066
 *
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
public class TruncatedHmacExtensionMessage extends ExtensionMessage {

    public TruncatedHmacExtensionMessage() {
        super(ExtensionType.TRUNCATED_HMAC);
    }

    @Override
    public TruncatedHmacExtensionHandler getHandler(TlsContext context) {
        return new TruncatedHmacExtensionHandler(context);
    }

}
