/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.bruteforce;

import java.io.InputStream;

public class GuessProviderFactory {

    public static GuessProvider createGuessProvider(GuessProviderType type, InputStream guessSource) {
        switch (type) {
            case INCREMENTING:
                return new IncrementingGuessProvider();
            case WORDLIST:
                return new WordListGuessProvider(guessSource);
            default:
                throw new UnsupportedOperationException("Guess provider \"" + type + "\" is not supported");
        }
    }

    private GuessProviderFactory() {
    }
}
