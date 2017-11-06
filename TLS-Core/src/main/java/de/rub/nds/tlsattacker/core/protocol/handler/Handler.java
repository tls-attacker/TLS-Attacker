/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.protocol.parser.Parser;
import de.rub.nds.tlsattacker.core.protocol.preparator.Preparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.Serializer;

/**
 * @param <T>
 *            The Object that should be Handled
 */
public abstract class Handler<T> {
    public abstract Parser getParser(byte[] message, int pointer);

    public abstract Preparator getPreparator(T message);

    public abstract Serializer getSerializer(T message);

    protected abstract void adjustContext(T object);
}
