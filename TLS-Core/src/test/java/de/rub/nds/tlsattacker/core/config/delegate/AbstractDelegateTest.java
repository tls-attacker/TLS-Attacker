/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.config.delegate;

import com.beust.jcommander.JCommander;

abstract class AbstractDelegateTest<T extends Delegate> {

    protected T delegate;

    protected JCommander jcommander;

    protected String[] args;

    public void setUp(T delegate) {
        this.delegate = delegate;
        this.jcommander = new JCommander(delegate);
    }
}
