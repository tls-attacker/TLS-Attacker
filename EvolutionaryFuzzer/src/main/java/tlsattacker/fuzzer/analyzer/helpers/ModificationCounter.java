/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.analyzer.helpers;

import tlsattacker.fuzzer.modification.ModificationType;

/**
 * A helper helper class for the ModificationRules to help counting.
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class ModificationCounter {

    private ModificationType type;

    private int counter = 0;

    public ModificationCounter(ModificationType type) {
        this.type = type;
    }

    /**
     * Get the value of counter
     * 
     * @return the value of counter
     */
    public int getCounter() {
        return counter;
    }

    /**
     * Set the value of counter
     * 
     * @param counter
     *            new value of counter
     */
    public void setCounter(int counter) {
        this.counter = counter;
    }

    /**
     * Increments the counter
     */
    public void incrementCounter() {
        this.counter++;
    }

    public ModificationType getType() {
        return type;
    }

    public void setType(ModificationType type) {
        this.type = type;
    }

}
