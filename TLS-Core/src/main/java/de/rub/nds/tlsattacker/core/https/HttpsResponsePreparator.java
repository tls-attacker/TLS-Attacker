/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.https;

import de.rub.nds.tlsattacker.core.https.header.ContentLengthHeader;
import de.rub.nds.tlsattacker.core.https.header.HttpHeader;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessagePreparator;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import java.nio.charset.StandardCharsets;

public class HttpsResponsePreparator extends HttpsMessagePreparator<HttpsResponseMessage> {

    private final HttpsResponseMessage message;

    public HttpsResponsePreparator(Chooser chooser, HttpsResponseMessage message) {
        super(chooser, message);
        this.message = message;
    }

    @Override
    protected void prepareHttpsMessageContents() {
        message.setResponseProtocol("HTTP/1.1");
        message.setResponseStatusCode("200 OK");
        message.setResponseContent(chooser.getConfig().getDefaultApplicationMessageData());

        for (HttpHeader header : message.getHeader()) {
            if (header instanceof ContentLengthHeader) {
                ((ContentLengthHeader) header).setConfigLength(
                    message.getResponseContent().getValue().getBytes(StandardCharsets.ISO_8859_1).length);
            }
            header.getPreparator(chooser).prepare();
        }
    }

}
