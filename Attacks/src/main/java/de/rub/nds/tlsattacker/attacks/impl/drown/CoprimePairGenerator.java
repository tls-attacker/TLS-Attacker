/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.attacks.impl.drown;

import java.math.BigInteger;
import java.util.Iterator;

/**
 * Base class for stateful generators which return pairs of coprime numbers for usage with Bleichenbacher "Trimmers" as
 * introduced by Bardou et al. 2012.
 */
abstract class CoprimePairGenerator implements Iterator<BigInteger[]> {

    protected long numberOfQueries = 0;

    public long getNumberOfQueries() {
        return numberOfQueries;
    }

}
