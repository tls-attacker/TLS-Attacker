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
import de.rub.nds.tlsattacker.core.workflow.TlsConfig;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class RenegotiationDelegate extends Delegate {

    @Parameter(names = "-legacy_renegotiation", description = "Enables use of legacy renegotiation")
    private Boolean legacyRenegotiation;

    public RenegotiationDelegate() {
    }

    public Boolean isLegacyRenegotiation() {
        return legacyRenegotiation;
    }

    public void setLegacyRenegotiation(boolean legacyRenegotiation) {
        this.legacyRenegotiation = legacyRenegotiation;
    }

    @Override
    public void applyDelegate(TlsConfig config) {
        if (legacyRenegotiation != null) {
            config.setRenegotiation(legacyRenegotiation);
        }
    }

}
