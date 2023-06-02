/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.http.header;

import de.rub.nds.tlsattacker.core.http.header.preparator.DateHeaderPreparator;
import de.rub.nds.tlsattacker.core.layer.context.HttpContext;

public class DateHeader extends HttpHeader {

    public DateHeader() {}

    @Override
    public DateHeaderPreparator getPreparator(HttpContext httpContext) {
        return new DateHeaderPreparator(httpContext.getChooser(), this);
    }
}
