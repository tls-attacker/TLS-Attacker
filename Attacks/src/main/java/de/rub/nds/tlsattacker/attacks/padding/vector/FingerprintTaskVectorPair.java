/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.padding.vector;

import de.rub.nds.tlsattacker.attacks.task.FingerPrintTask;

/**
 *
 */
public class FingerprintTaskVectorPair {

    private final FingerPrintTask fingerPrintTask;

    private final PaddingVector vector;

    public FingerprintTaskVectorPair(FingerPrintTask fingerPrintTask, PaddingVector vector) {
        this.fingerPrintTask = fingerPrintTask;
        this.vector = vector;
    }

    public FingerPrintTask getFingerPrintTask() {
        return fingerPrintTask;
    }

    public PaddingVector getVector() {
        return vector;
    }

    @Override
    public String toString() {
        return "FingerprintTaskVectorPair{" + "fingerPrintTask=" + fingerPrintTask + ", vector=" + vector + '}';
    }

}
