/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol;

/**
 * @param <T>
 * The Object that should be Handled
 */
public abstract class Handler<T> {
    public abstract Parser<T> getParser(byte[] message, int pointer);

    public abstract Preparator<T> getPreparator(T message);

    public abstract Serializer<T> getSerializer(T message);

    public abstract void adjustContext(T object);
}
