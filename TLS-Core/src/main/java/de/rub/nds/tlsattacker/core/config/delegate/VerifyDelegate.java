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
import de.rub.nds.tlsattacker.core.config.Config;

public class VerifyDelegate extends Delegate {

    @Parameter(
            names = {"-Verify", "-verify"},
            description =
                    "Request and require client certificate. The value specifies the verification depth (similar to OpenSSL -Verify)")
    private Integer verifyDepth;

    public VerifyDelegate() {}

    public Integer getVerifyDepth() {
        return verifyDepth;
    }

    public void setVerifyDepth(Integer verifyDepth) {
        this.verifyDepth = verifyDepth;
    }

    @Override
    public void applyDelegate(Config config) {
        if (verifyDepth != null) {
            config.setClientAuthentication(true);
        }
    }
}
