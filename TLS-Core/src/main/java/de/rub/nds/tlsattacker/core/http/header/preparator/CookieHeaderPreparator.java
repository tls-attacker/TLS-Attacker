/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.http.header.preparator;

import de.rub.nds.tlsattacker.core.http.header.CookieHeader;
import de.rub.nds.tlsattacker.core.layer.context.HttpContext;
import de.rub.nds.tlsattacker.core.layer.data.Preparator;
import org.apache.commons.lang3.StringUtils;

public class CookieHeaderPreparator extends Preparator<CookieHeader> {

    private final CookieHeader header;

    public CookieHeaderPreparator(HttpContext httpContext, CookieHeader header) {
        super(httpContext.getChooser(), header);
        this.header = header;
    }

    @Override
    public void prepare() {
        header.setHeaderName("Cookie");
        String headerValue =
                StringUtils.join(chooser.getHttpCookieName(), '=', chooser.getHttpCookieValue());
        header.setHeaderValue(headerValue);
    }
}
