/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.https.header.handler;

import de.rub.nds.tlsattacker.core.https.header.HttpsHeader;
import de.rub.nds.tlsattacker.core.protocol.handler.Handler;
import de.rub.nds.tlsattacker.core.state.http.HttpContext;

public abstract class HttpsHeaderHandler extends Handler<HttpsHeader> {

    private final HttpContext context;

    public HttpsHeaderHandler(HttpContext context) {
        this.context = context;
    }
}
