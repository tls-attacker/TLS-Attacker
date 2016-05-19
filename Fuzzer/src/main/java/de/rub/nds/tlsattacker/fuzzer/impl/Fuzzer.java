/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.fuzzer.impl;

import de.rub.nds.tlsattacker.tls.config.GeneralConfig;

/**
 * 
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 */
public abstract class Fuzzer {

    GeneralConfig generalConfig;

    public Fuzzer(GeneralConfig config) {
	this.generalConfig = config;
    }

    /**
     * Starts fuzzing, should be implemented in every fuzzer
     */
    public abstract void startFuzzer();
}
