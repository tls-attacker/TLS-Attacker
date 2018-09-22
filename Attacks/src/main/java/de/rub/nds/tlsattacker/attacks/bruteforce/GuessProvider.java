/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.bruteforce;

/**
 * A GuessProvider is responsible for the creation of byte[] sequences for brute
 * force attacks. The guess provider should minimize the number of guesses
 * according to heuristics.
 */
public abstract class GuessProvider {

    private final GuessProviderType type;

    /**
     * Constructor
     *
     * @param type
     *            Type of the GuessProvider
     */
    public GuessProvider(GuessProviderType type) {
        this.type = type;
    }

    /**
     * Returns the next guess for the attack. Guesses should not repeat, but it
     * is not completly prohibited by this API. Returns null if no more guesses
     * are available.
     *
     * @return The next byte[] to be used in the brute force attack.
     */
    public abstract byte[] getGuess();

    /**
     * Retunrs the type of this GuessProvider
     *
     * @return Type of this GuessProvider
     */
    public GuessProviderType getType() {
        return type;
    }
}
