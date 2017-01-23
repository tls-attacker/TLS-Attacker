/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.testhelper;

import java.util.LinkedList;
import java.util.Random;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class MockedRandom extends Random {

    private LinkedList<Integer> queue;

    public MockedRandom() {
        queue = new LinkedList<>();
    }

    public void addNumber(int number) {
        queue.addFirst(number);
    }

    @Override
    public long nextLong() {
        return queue.pop();
    }

    @Override
    public int nextInt(int n) {
        return queue.pop() % n;
    }

    @Override
    public int nextInt() {
        return queue.pop();
    }

    @Override
    protected int next(int bits) {
        return queue.pop();
    }
}
