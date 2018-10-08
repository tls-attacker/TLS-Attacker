/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.ec;

import java.util.Comparator;

/**
 *
 *
 */
public class ICEPointCopmparator implements Comparator<ICEPoint> {

    /**
     *
     * @param o1
     * @param o2
     * @return
     */
    @Override
    public int compare(ICEPoint o1, ICEPoint o2) {
        return Integer.compare(o1.getOrder(), o2.getOrder());
    }

}
