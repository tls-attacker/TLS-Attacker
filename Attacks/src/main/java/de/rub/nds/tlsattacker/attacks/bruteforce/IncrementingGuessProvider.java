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
 *
 * @author robert
 */
public class IncrementingGuessProvider extends GuessProvider {

    private byte[] lastGuess = null;

    private int size = 0;

    /**
     *
     */
    public IncrementingGuessProvider() {
        super(GuessProviderType.INCREMENTING);
    }

    /**
     *
     * @return
     */
    @Override
    public byte[] getGuess() {
        byte[] guess = getIncrementedGuess();
        return guess;
    }

    /**
     *
     * @return
     */
    public byte[] getIncrementedGuess() {
        if (lastGuess == null) {
            lastGuess = new byte[size];
        } else {
            lastGuess = createdIncrementedAtPosition(lastGuess, 0);
            if (lastGuess == null) {
                size++;
                lastGuess = new byte[size];
            }
        }
        return lastGuess;
    }

    /**
     *
     * @param array
     * @param position
     * @return
     */
    public byte[] createdIncrementedAtPosition(byte[] array, int position) {
        if (array.length > position) {
            array[position] = (byte) (array[position] + 1);
            if (array[position] == 0) {
                return createdIncrementedAtPosition(array, position + 1);
            }
            return array;
        } else {
            return null;
        }
    }
}
