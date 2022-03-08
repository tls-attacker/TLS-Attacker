/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.https;

import de.rub.nds.tlsattacker.core.protocol.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.state.http.HttpContext;

public class HttpsResponseHandler extends HttpsMessageHandler<HttpsResponseMessage> {

    TlsContext tlsContext;

    public HttpsResponseHandler(TlsContext tlsContext) {
        this.tlsContext = tlsContext;
    }

    @Override
    public void adjustContext(HttpsResponseMessage message) {
    }

}
