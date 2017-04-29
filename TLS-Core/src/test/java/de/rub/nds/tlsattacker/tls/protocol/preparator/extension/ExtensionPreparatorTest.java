/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.preparator.extension;

import de.rub.nds.tlsattacker.tls.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;

/**
 *
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
public abstract class ExtensionPreparatorTest {
    
    protected TlsContext context;
    protected ExtensionMessage message;
    protected ExtensionPreparator preparator;
    
}
