/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.http.header;

import de.rub.nds.tlsattacker.core.http.header.preparator.CookieHeaderPreparator;
import de.rub.nds.tlsattacker.core.layer.context.HttpContext;
import de.rub.nds.tlsattacker.core.layer.data.Handler;
import de.rub.nds.tlsattacker.core.layer.data.Parser;
import de.rub.nds.tlsattacker.core.layer.data.Serializer;
import java.io.InputStream;

public class CookieHeader extends HttpHeader {

    public CookieHeader() {}

    @Override
    public CookieHeaderPreparator getPreparator(HttpContext httpContext) {
        return new CookieHeaderPreparator(httpContext, this);
    }

    @Override
    public Parser<?> getParser(HttpContext context, InputStream stream) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'getParser'");
    }

    @Override
    public Serializer<?> getSerializer(HttpContext context) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'getSerializer'");
    }

    @Override
    public Handler<?> getHandler(HttpContext context) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'getHandler'");
    }
}
