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
import de.rub.nds.tlsattacker.core.stun.model.ErrorCodeAttribute;

public class ErrorCodeAttributeHandler extends StunAttributeHandler<ErrorCodeAttribute> {

    public ErrorCodeAttributeHandler(IceContext context) {
        super(context);
    }

    @Override
    public void adjustContext(ErrorCodeAttribute container) {
        context.setStunErrorCode(container.getNumber().getValue());
    }
}
