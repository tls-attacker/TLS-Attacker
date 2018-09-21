/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.config.delegate;

import com.beust.jcommander.Parameter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.converters.StarttlsTypeConverter;
import de.rub.nds.tlsattacker.core.constants.StarttlsType;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;

public class StarttlsDelegate extends Delegate {

    @Parameter(names = "-starttls", required = false, description = "Starttls protocol. Choose from ftp, imap, pop3, smtp.", converter = StarttlsTypeConverter.class)
    private StarttlsType starttlsType = StarttlsType.NONE;

    public StarttlsDelegate() {

    }

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
