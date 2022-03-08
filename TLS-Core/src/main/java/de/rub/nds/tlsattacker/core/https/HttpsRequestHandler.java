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

public class HttpsRequestHandler extends HttpsMessageHandler<HttpsRequestMessage> {

    // TODO: REMOVE IN CONTEXT SPLITTING
    TlsContext tlsContext;

    public HttpsRequestHandler(TlsContext tlsContext) {
        this.tlsContext = tlsContext;
    }

    public void adjustContext(HttpsRequestMessage message) {
        tlsContext.getHttpContext().setLastRequestPath(message.getRequestPath().getValue());
    }

}
