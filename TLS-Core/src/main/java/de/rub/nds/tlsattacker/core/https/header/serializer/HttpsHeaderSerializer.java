/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.https.header.serializer;

import de.rub.nds.tlsattacker.core.https.header.HttpHeader;
import java.nio.charset.StandardCharsets;
import de.rub.nds.tlsattacker.core.protocol.Serializer;

public class HttpsHeaderSerializer extends Serializer<HttpHeader> {

    private final HttpHeader header;

    public HttpsHeaderSerializer(HttpHeader header) {
        super();
        this.header = header;
    }

    @Override
    protected byte[] serializeBytes() {
        appendBytes(header.getHeaderName().getValue().getBytes(StandardCharsets.ISO_8859_1));
        appendBytes(": ".getBytes());
        appendBytes(header.getHeaderValue().getValue().getBytes(StandardCharsets.ISO_8859_1));
        appendBytes("\r\n".getBytes());
        return getAlreadySerialized();
    }
}
