/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.stun.handler;

import de.rub.nds.tlsattacker.core.layer.context.IceContext;
import de.rub.nds.tlsattacker.core.layer.data.Handler;
import de.rub.nds.tlsattacker.core.stun.model.StunAttribute;

public abstract class StunAttributeHandler<AttributeT extends StunAttribute>
        extends Handler<AttributeT> {

    protected final IceContext context;

    public StunAttributeHandler(IceContext context) {
        this.context = context;
    }
}
