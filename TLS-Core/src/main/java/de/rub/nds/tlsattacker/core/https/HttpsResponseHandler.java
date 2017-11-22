/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.https;

import de.rub.nds.tlsattacker.core.protocol.handler.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.core.state.TlsContext;

public class HttpsResponseHandler extends ProtocolMessageHandler<HttpsResponseMessage> {

    public HttpsResponseHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public HttpsResponseParser getParser(byte[] message, int pointer) {
        return new HttpsResponseParser(pointer, message, tlsContext.getChooser().getSelectedProtocolVersion());
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
