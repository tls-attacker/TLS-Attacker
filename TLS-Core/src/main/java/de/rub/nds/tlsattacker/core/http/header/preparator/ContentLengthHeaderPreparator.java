/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.http.header.preparator;

import de.rub.nds.tlsattacker.core.http.header.ContentLengthHeader;
import de.rub.nds.tlsattacker.core.layer.context.HttpContext;
import de.rub.nds.tlsattacker.core.layer.data.Preparator;

public class ContentLengthHeaderPreparator extends Preparator<ContentLengthHeader> {

    private final ContentLengthHeader header;

    public ContentLengthHeaderPreparator(HttpContext httpContext, ContentLengthHeader header) {
        super(httpContext.getChooser(), header);
        this.header = header;
    }

    @Override
    public void prepare() {
        header.setHeaderName("Content-Length");
        header.setLength(header.getConfigLength());
        header.setHeaderValue("" + header.getLength().getValue());
    }
}
