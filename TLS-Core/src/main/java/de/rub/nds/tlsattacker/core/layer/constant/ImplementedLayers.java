/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.layer.constant;

/** Holds all implemented layers of the TLS-Core, not limited to any layer of the ISO stack */
public enum ImplementedLayers implements LayerType {
    TCP,
    UDP,
    // Record + Message layer are both part of TLS
    RECORD,
    MESSAGE,
    DTLS_FRAGMENT,
    HTTP,
    SSL2;

    @Override
    public String getName() {
        return this.name();
    }
}
