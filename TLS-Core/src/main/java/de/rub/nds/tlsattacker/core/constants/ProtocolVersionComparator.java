/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.constants;

import java.util.Comparator;

class ProtocolVersionComparator implements Comparator<ProtocolVersion> {

    @Override
    public int compare(ProtocolVersion o1, ProtocolVersion o2) {
        return o1.compare(o2);
    }
}
