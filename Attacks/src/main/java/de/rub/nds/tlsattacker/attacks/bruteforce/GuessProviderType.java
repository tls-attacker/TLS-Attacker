/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */

package de.rub.nds.tlsattacker.attacks.bruteforce;

/**
 * A Type of GuessProvider.
 */
public enum GuessProviderType {

    /**
     * An IncrementingGuessProvider just tries all byte[] sequences in order
     */
    INCREMENTING,
    /**
     * A WordListGuessProvider uses an InputSource to try all words from the InputSource
     */
    WORDLIST
}
