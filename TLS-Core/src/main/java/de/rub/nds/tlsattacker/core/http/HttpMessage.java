/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.http;

import de.rub.nds.tlsattacker.core.layer.Message;
import de.rub.nds.tlsattacker.core.layer.context.HttpContext;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlSeeAlso;
import java.io.InputStream;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlSeeAlso({HttpRequestMessage.class, HttpResponseMessage.class})
public abstract class HttpMessage<Self extends HttpMessage<?>> extends Message<Self, HttpContext> {

    @Override
    public abstract HttpMessageHandler<Self> getHandler(HttpContext context);

    @Override
    public abstract HttpMessageSerializer<Self> getSerializer(HttpContext context);

    @Override
    public abstract HttpMessagePreparator<Self> getPreparator(HttpContext context);

    @Override
    public abstract HttpMessageParser<Self> getParser(HttpContext context, InputStream stream);
}
