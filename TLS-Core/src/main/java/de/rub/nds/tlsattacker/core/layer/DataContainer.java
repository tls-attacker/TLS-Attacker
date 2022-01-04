/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.layer;

import de.rub.nds.tlsattacker.core.protocol.Handler;
import de.rub.nds.tlsattacker.core.protocol.Parser;
import de.rub.nds.tlsattacker.core.protocol.Preparator;
import de.rub.nds.tlsattacker.core.protocol.Serializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;

import java.io.InputStream;

public interface DataContainer<T extends DataContainer> {

    public Parser<T> getParser(TlsContext context, InputStream stream);

    // TODO Replace with Context
    public Preparator<T> getPreparator(TlsContext context);

    // TODO Replace with Context
    public Serializer<T> getSerializer(TlsContext context);

    // TODO Replace with Context
    public Handler<T> getHandler(TlsContext context);
}
