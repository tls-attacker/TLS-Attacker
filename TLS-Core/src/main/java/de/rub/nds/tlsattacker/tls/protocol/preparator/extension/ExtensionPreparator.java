/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.preparator.extension;

import de.rub.nds.tlsattacker.tls.protocol.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.tls.protocol.preparator.Preparator;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 * @param <T>
 */
public abstract class ExtensionPreparator<T extends ExtensionMessage> extends Preparator<T> {

    public ExtensionPreparator(TlsContext context, T object) {
        super(context, object);
    }

}
