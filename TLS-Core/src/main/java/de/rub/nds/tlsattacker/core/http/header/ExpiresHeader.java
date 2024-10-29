/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.http.header;

import de.rub.nds.tlsattacker.core.http.header.preparator.ExpiresHeaderPreparator;
import de.rub.nds.tlsattacker.core.http.header.serializer.HttpHeaderSerializer;
import de.rub.nds.tlsattacker.core.layer.data.Handler;
import de.rub.nds.tlsattacker.core.layer.data.Parser;
import de.rub.nds.tlsattacker.core.state.Context;
import java.io.InputStream;

public class ExpiresHeader extends HttpHeader {

    @Override
    public ExpiresHeaderPreparator getPreparator(Context context) {
        return new ExpiresHeaderPreparator(context.getChooser(), this);
    }

    @Override
    public Parser<ExpiresHeader> getParser(Context context, InputStream stream) {
        return null; // TODO Parser is not used
    }

    @Override
    public HttpHeaderSerializer getSerializer(Context context) {
        return new HttpHeaderSerializer(this);
    }

    @Override
    public Handler<ExpiresHeader> getHandler(Context context) {
        return null;
    }
}
