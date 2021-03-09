/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
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
