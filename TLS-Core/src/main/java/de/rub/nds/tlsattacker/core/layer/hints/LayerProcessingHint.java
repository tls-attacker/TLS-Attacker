/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.layer.hints;

/**
 * Lower layers sometimes need a hint for which data they need to receive. This a
 * LayerProcessingHint carries the necessary information.
 */
public interface LayerProcessingHint {

    @Override
    public boolean equals(Object o);
}
