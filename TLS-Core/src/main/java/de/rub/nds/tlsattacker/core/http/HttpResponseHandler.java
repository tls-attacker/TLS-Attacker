/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.http;

import de.rub.nds.tlsattacker.core.protocol.Handler;

public class HttpResponseHandler implements Handler<HttpResponseMessage> {

    public HttpResponseHandler() {

    }

    public void adjustContext(HttpResponseMessage message) {
    }
}
