/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.impl.drown;

import java.math.BigInteger;
import java.util.Iterator;

/**
 * Base class for stateful generators which return pairs of coprime numbers for
 * usage with Bleichenbacher "Trimmers" as introduced by Bardou et al. 2012.
 */
abstract class CoprimePairGenerator implements Iterator<BigInteger[]> {

    protected long numberOfQueries = 0;

    public long getNumberOfQueries() {
        return numberOfQueries;
    }

}
