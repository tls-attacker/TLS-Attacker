/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow;

import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;

public class NamedThreadFactory implements ThreadFactory {

    private int number;

    private final String prefix;

    public NamedThreadFactory(String prefix) {
        this.number = 1;
        this.prefix = prefix;
    }

    @Override
    public Thread newThread(Runnable r) {
        Thread newThread = Executors.defaultThreadFactory().newThread(r);
        newThread.setName(prefix + "-" + number);
        number++;
        return newThread;
    }

}
