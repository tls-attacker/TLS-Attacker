/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.https;

import de.rub.nds.tlsattacker.core.protocol.handler.TlsMessageHandler;
import de.rub.nds.tlsattacker.core.state.TlsContext;

public class HttpsResponseHandler extends TlsMessageHandler<HttpsResponseMessage> {

    public HttpsResponseHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public HttpsResponseParser getParser(byte[] message, int pointer) {
        return new HttpsResponseParser(pointer, message, tlsContext.getChooser().getSelectedProtocolVersion(),
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
