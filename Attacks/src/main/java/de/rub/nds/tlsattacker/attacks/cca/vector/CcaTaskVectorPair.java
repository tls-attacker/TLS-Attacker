/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.attacks.cca.vector;

import de.rub.nds.tlsattacker.attacks.task.CcaTask;

/**
 *
 */
public class CcaTaskVectorPair {

    private final CcaTask ccaTask;

    private final CcaVector ccaVector;

    public CcaTaskVectorPair(CcaTask ccaTask, CcaVector vector) {
        this.ccaTask = ccaTask;
        this.ccaVector = vector;
    }

    public CcaTask getCcaTask() {
        return ccaTask;
    }

    public CcaVector getVector() {
        return ccaVector;
    }

    @Override
    public String toString() {
        return "CcaProbeTaskVectorPair{" + "ccaTask=" + ccaTask + ", vector=" + ccaVector + '}';
    }

}
