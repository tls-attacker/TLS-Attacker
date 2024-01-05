/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow;

import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;

public class NamedThreadFactory implements ThreadFactory {

    private int number;

    private final String prefix;

    private boolean includeNumber;

    public NamedThreadFactory(String prefix) {
        this(prefix, true);
    }

    public NamedThreadFactory(String prefix, boolean includeNumber) {
        this.number = 1;
        this.prefix = prefix;
        this.includeNumber = includeNumber;
    }

    @Override
    public Thread newThread(Runnable r) {
        Thread newThread = Executors.defaultThreadFactory().newThread(r);
        if (includeNumber) {
            newThread.setName(prefix + "-" + number);
            number++;
        } else {
            newThread.setName(prefix);
        }
        return newThread;
    }
}
