/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.unittest.helper;

import java.util.Objects;
import java.util.function.Function;

@FunctionalInterface
public interface QuadFunction<A, B, C, D, R> {

    R apply(A a, B b, C c, D d);

    default <V> QuadFunction<A, B, C, D, V> andThen(Function<? super R, ? extends V> after) {
        Objects.requireNonNull(after);
        return (a, b, c, d) -> after.apply(apply(a, b, c, d));
    }
}
