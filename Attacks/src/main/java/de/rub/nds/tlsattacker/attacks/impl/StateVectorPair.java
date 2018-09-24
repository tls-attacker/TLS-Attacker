/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.impl;

import de.rub.nds.tlsattacker.attacks.pkcs1.Pkcs1Vector;
import de.rub.nds.tlsattacker.core.state.State;

/**
 *
 */
public class StateVectorPair {

    private State state;

    private Pkcs1Vector vector;

    /**
     *
     * @param state
     * @param vector
     */
    public StateVectorPair(State state, Pkcs1Vector vector) {
        this.state = state;
        this.vector = vector;
    }

    /**
     *
     * @return
     */
    public State getState() {
        return state;
    }

    /**
     *
     * @param state
     */
    public void setState(State state) {
        this.state = state;
    }

    /**
     *
     * @return
     */
    public Pkcs1Vector getVector() {
        return vector;
    }

    /**
     *
     * @param vector
     */
    public void setVector(Pkcs1Vector vector) {
        this.vector = vector;
    }

}
