/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.UnknownExtensionMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 * @param <T>
 */
public class UnknownExtensionPreparator<T extends UnknownExtensionMessage> extends ExtensionPreparator<T> {

    private final UnknownExtensionMessage msg;

    public UnknownExtensionPreparator(TlsContext context, T object) {
        super(context, object);
        msg = object;
    }

    @Override
    public void prepareExtensionContent() {
        msg.setExtensionData(msg.getDataConfig());
        msg.setExtensionType(msg.getTypeConfig());
        msg.setExtensionLength(msg.getLengthConfig());
    }

}
