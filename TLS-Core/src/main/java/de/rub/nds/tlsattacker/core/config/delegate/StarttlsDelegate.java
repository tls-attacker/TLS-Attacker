/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.config.delegate;

import com.beust.jcommander.Parameter;
import de.rub.nds.protocol.exception.ConfigurationException;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.StarttlsType;

public class StarttlsDelegate extends Delegate {

    @Parameter(names = "-starttls", required = false, description = "Starttls protocol")
    private StarttlsType starttlsType = StarttlsType.NONE;

    public StarttlsDelegate() {}

    public StarttlsType getStarttlsType() {
        return starttlsType;
    }

    public void setStarttlsType(StarttlsType starttlsType) {
        this.starttlsType = starttlsType;
    }

    @Override
    public void applyDelegate(Config config) throws ConfigurationException {
        config.setStarttlsType(starttlsType);
    }
}
