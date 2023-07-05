/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.http.header;

import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.tlsattacker.core.http.header.preparator.TokenBindingHeaderPreparator;
import de.rub.nds.tlsattacker.core.layer.context.HttpContext;
import de.rub.nds.tlsattacker.core.tokenbinding.TokenBindingMessage;

public class TokenBindingHeader extends HttpHeader {

    @HoldsModifiableVariable private TokenBindingMessage message;

    public TokenBindingHeader() {
        message = new TokenBindingMessage();
    }

    public TokenBindingMessage getMessage() {
        return message;
    }

    public void setMessage(TokenBindingMessage message) {
        this.message = message;
    }

    @Override
    public TokenBindingHeaderPreparator getPreparator(HttpContext httpContext) {
        return new TokenBindingHeaderPreparator(httpContext, this);
    }
}
