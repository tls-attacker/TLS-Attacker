/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.layer.constant;

// TODO: only ImplementedLayer implements this and enum has those methods built-in. Do we need this interface?
public interface LayerType {
    public String getName();

    public default boolean equals(LayerType other) {
        return other.getName().equals(this.getName());
    }
}
