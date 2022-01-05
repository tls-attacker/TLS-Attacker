/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol;

/**
 * @param <T>
 *            The Object that should be Handled
 */
public interface Handler<T> {

    Parser<T> getParser(byte[] message, int pointer);

    Preparator<T> getPreparator(T message);

    Serializer<T> getSerializer(T message);

    void adjustContext(T object);
}
