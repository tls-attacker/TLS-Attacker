/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.bruteforce;

public abstract class GuessProvider {

    private final GuessProviderType type;

    public GuessProvider(GuessProviderType type) {
        this.type = type;
    }

    public abstract byte[] getGuess();

    public GuessProviderType getType() {
        return type;
    }
}
