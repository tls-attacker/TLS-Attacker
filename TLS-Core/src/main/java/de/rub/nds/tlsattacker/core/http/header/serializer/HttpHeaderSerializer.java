/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.http.header.serializer;

import de.rub.nds.tlsattacker.core.http.header.HttpHeader;
import de.rub.nds.tlsattacker.core.layer.data.Serializer;
import java.nio.charset.StandardCharsets;

public class HttpHeaderSerializer extends Serializer<HttpHeader> {

    private final HttpHeader header;

    public HttpHeaderSerializer(HttpHeader header) {
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
