/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.stun.handler;

import de.rub.nds.tlsattacker.core.stun.IceContext;
import de.rub.nds.tlsattacker.core.stun.model.MessageIntegrityAttribute;

public class MessageIntegrityHandler extends StunAttributeHandler<MessageIntegrityAttribute> {

    public MessageIntegrityHandler(IceContext context) {
        super(context);
    }

    @Override
    public void adjustContext(MessageIntegrityAttribute container) {
        // Nothing to do
    }
}
