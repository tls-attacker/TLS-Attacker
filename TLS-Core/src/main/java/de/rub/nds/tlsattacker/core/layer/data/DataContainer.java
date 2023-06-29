/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.layer.data;

import de.rub.nds.tlsattacker.core.layer.context.LayerContext;
import java.io.InputStream;

/**
 * All protocol messages are abstracted with the DataContainer interface. For TLS-Attacker to work
 * with data it only needs to know how to parse, prepare, serialize and handle the message. All
 * messages must therefore provide this functionality.
 */
public interface DataContainer<
        Container extends DataContainer<?, ?>, Context extends LayerContext> {

    public Parser<Container> getParser(Context context, InputStream stream);

    public Preparator<Container> getPreparator(Context context);

    public Serializer<Container> getSerializer(Context context);

    public Handler<Container> getHandler(Context context);

    public default boolean isRequired() {
        return true;
    }

    public default String toCompactString() {
        return toString();
    }

    public default String toShortString() {
        return toCompactString();
    }
}
