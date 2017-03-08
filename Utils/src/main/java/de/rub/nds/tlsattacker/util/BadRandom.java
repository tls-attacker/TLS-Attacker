/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.util;

import java.security.Provider;
import java.security.SecureRandom;
import java.security.SecureRandomSpi;
import java.util.Random;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class BadRandom extends SecureRandom {

    private Random r;

    public BadRandom() {
        r = new Random(0);
    }

    public BadRandom(Random r, byte[] seed) {
        this.r = r;
    }

    public BadRandom(Random r, SecureRandomSpi secureRandomSpi, Provider provider) {
        this.r = r;
    }

    @Override
    public byte[] generateSeed(int numBytes) {
        byte[] ray = new byte[numBytes];
        r.nextBytes(ray);
        return ray;
    }

    @Override
    public synchronized void nextBytes(byte[] bytes) {
        r.nextBytes(bytes);

    }

    @Override
    public void setSeed(long seed) {
        r = new Random(seed);
    }

    @Override
    public synchronized void setSeed(byte[] seed) {
        throw new UnsupportedOperationException();
    }

    @Override
    public String getAlgorithm() {
        return "WARNING: We use the default JAVA PRNG. THIS IS NOT A SECURE RANDOM OBJECT. USE FOR FUZZING ONLY";
    }

    @Override
    public int nextInt() {
        return r.nextInt();
    }

    @Override
    public int nextInt(int n) {
        return r.nextInt(n);
    }

    @Override
    public long nextLong() {
        return r.nextLong();
    }

    @Override
    public boolean nextBoolean() {
        return r.nextBoolean();
    }

    @Override
    public float nextFloat() {
        return r.nextFloat();
    }

    @Override
    public double nextDouble() {
        return r.nextDouble();
    }

    @Override
    public synchronized double nextGaussian() {
        return r.nextGaussian();
    }

}
