/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.https;

import de.rub.nds.tlsattacker.core.protocol.handler.TlsMessageHandler;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.io.InputStream;

public class HttpsRequestHandler extends TlsMessageHandler<HttpsRequestMessage> {

    public HttpsRequestHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public void adjustTLSContext(HttpsRequestMessage message) {
        tlsContext.getHttpContext().setLastRequestPath(message.getRequestPath().getValue());
    }

}
