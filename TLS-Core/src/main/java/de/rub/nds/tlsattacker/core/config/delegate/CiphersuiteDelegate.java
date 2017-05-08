/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.config.delegate;

import com.beust.jcommander.Parameter;
import de.rub.nds.tlsattacker.core.config.converters.CipherSuiteConverter;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.workflow.TlsConfig;
import java.util.Collections;
import java.util.List;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class CiphersuiteDelegate extends Delegate {

    @Parameter(names = "-cipher", description = "TLS Ciphersuites to use, divided by a comma, e.g. "
            + "TLS_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_CBC_SHA", converter = CipherSuiteConverter.class)
    private List<CipherSuite> cipherSuites = null;

    public CiphersuiteDelegate() {
    }

    public List<CipherSuite> getCipherSuites() {
        if (cipherSuites == null) {
            return null;
        }
        return Collections.unmodifiableList(cipherSuites);
    }

    public void setCipherSuites(List<CipherSuite> cipherSuites) {
        this.cipherSuites = cipherSuites;
    }

    @Override
    public void applyDelegate(TlsConfig config) {
        if (cipherSuites != null) {
            config.setSupportedCiphersuites(cipherSuites);
        }
    }

}
