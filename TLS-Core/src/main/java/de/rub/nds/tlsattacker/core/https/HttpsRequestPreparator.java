/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.https;

import de.rub.nds.tlsattacker.core.https.header.HttpsHeader;
import de.rub.nds.tlsattacker.core.protocol.preparator.ProtocolMessagePreparator;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

public class HttpsRequestPreparator extends ProtocolMessagePreparator<HttpsRequestMessage> {

    private final HttpsRequestMessage message;

    public HttpsRequestPreparator(Chooser chooser, HttpsRequestMessage message) {
        super(chooser, message);
        this.message = message;
    }

    @Override
    protected void prepareProtocolMessageContents() {
        message.setRequestPath("/");
        message.setRequestProtocol("HTTP/1.1");
        message.setRequestType("GET");
        for (HttpsHeader header : message.getHeader()) {
            header.getPreparator(chooser).prepare();
        }
    }

}
