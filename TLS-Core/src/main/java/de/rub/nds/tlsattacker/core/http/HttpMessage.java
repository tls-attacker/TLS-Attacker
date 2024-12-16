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
import de.rub.nds.tlsattacker.core.state.Context;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlSeeAlso;
import java.io.InputStream;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlSeeAlso({HttpRequestMessage.class, HttpResponseMessage.class})
public abstract class HttpMessage extends Message {

    @Override
    public abstract HttpMessageHandler<? extends HttpMessage> getHandler(Context httpContext);

    @Override
    public abstract HttpMessageParser<? extends HttpMessage> getParser(
            Context context, InputStream stream);

    @Override
    public abstract HttpMessagePreparator<? extends HttpMessage> getPreparator(Context context);

    @Override
    public abstract HttpMessageSerializer<? extends HttpMessage> getSerializer(Context context);
}
