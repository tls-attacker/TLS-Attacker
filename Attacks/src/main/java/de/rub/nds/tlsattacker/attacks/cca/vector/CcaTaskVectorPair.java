/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.cca.vector;

import de.rub.nds.tlsattacker.attacks.padding.vector.PaddingVector;
import de.rub.nds.tlsattacker.attacks.task.CcaTask;
import de.rub.nds.tlsattacker.attacks.task.FingerPrintTask;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;

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
