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

public class HttpsResponseHandler extends TlsMessageHandler<HttpsResponseMessage> {

    public HttpsResponseHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public HttpsResponseParser getParser(InputStream stream) {
        return new HttpsResponseParser(stream, tlsContext.getChooser().getSelectedProtocolVersion(),
            tlsContext.getConfig());
    }

    @Override
    public HttpsResponsePreparator getPreparator(HttpsResponseMessage message) {
        return new HttpsResponsePreparator(tlsContext.getChooser(), message);
    }

    @Override
    public HttpsResponseSerializer getSerializer(HttpsResponseMessage message) {
        return new HttpsResponseSerializer(message, tlsContext.getChooser().getSelectedProtocolVersion());
    }

    @Override
    public void adjustTLSContext(HttpsResponseMessage message) {
    }

}
