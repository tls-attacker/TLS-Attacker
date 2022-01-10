/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.layer;

import java.io.InputStream;

import de.rub.nds.tlsattacker.core.layer.context.LayerContext;
import de.rub.nds.tlsattacker.core.protocol.Handler;
import de.rub.nds.tlsattacker.core.protocol.Parser;
import de.rub.nds.tlsattacker.core.protocol.Preparator;
import de.rub.nds.tlsattacker.core.protocol.Serializer;

public interface DataContainer<T extends DataContainer, U extends LayerContext> {

    public Parser<T> getParser(U context, InputStream stream);

    public Preparator<T> getPreparator(U context);

    public Serializer<T> getSerializer(U context);

    public Handler<T> getHandler(U context);

    public default boolean isRequired() {
        return true;
    }
}
