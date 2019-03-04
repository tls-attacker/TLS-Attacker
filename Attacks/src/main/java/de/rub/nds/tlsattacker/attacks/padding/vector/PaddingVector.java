/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.padding.vector;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.record.Record;

/**
 *
 */
public abstract class PaddingVector {

    protected final String name;

    protected final String identifier;

    public PaddingVector(String name, String identifier) {
        this.name = name;
        this.identifier = identifier;
    }

    public abstract Record createRecord();

    public abstract int getRecordLength(CipherSuite testedSuite, ProtocolVersion testedVersion, int appDataLength);

    public String getName() {
        return name;
    }

    public String getIdentifier() {
        return identifier;
    }
}
