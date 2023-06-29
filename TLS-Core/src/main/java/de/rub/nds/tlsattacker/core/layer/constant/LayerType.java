/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.layer.constant;

/**
 * Interface for Implemented Layers. As Implemented Layers might differ between
 * TLS-Attacker/SSH-Attacker etc. we need this interface.
 */
public interface LayerType {

    public String getName();

    public default boolean equals(LayerType other) {
        return other.getName().equals(this.getName());
    }
}
