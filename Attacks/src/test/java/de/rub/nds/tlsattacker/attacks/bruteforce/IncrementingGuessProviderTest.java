/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.attacks.bruteforce;

import org.junit.Before;
import org.junit.Test;

/**
 *
 *
 */
public class IncrementingGuessProviderTest {

    /**
     *
     */
    public IncrementingGuessProviderTest() {
    }

    /**
     *
     */
    @Before
    public void setUp() {
    }

    /**
     * Test of getGuess method, of class IncrementingGuessProvider.
     */
    @Test
    public void testGetGuess() {
        IncrementingGuessProvider provider = new IncrementingGuessProvider();
        for (int i = 0; i < 2048; i++) {
            provider.getGuess();
        }
    }
}
