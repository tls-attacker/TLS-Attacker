/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.http;

import de.rub.nds.tlsattacker.core.layer.data.Serializer;

public abstract class HttpMessageSerializer<T extends HttpMessage> extends Serializer<T> {

    protected final T message;

    public HttpMessageSerializer(T message) {
        this.message = message;
    }

    @Override
    public final byte[] serializeBytes() {
        return serializeHttpMessageContent();
    }

    public abstract byte[] serializeHttpMessageContent();

}