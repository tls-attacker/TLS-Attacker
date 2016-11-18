/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.testtls.config;

import com.beust.jcommander.Parameter;
import de.rub.nds.tlsattacker.tls.config.ClientCommandConfig;

/**
 * Configuration for testing TLS server capabilities. By now, per default all
 * the checks are performed. In the future, more fine granular tests can be
 * executed, as is the case in testssl.sh. See also the commented out variables.
 * 
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 */
public class TestServerConfig extends ClientCommandConfig {

    public static final String COMMAND = "testtls_server";

    // @Parameter(names = "-all", description = "Performs all checks.")
    // protected boolean all = true;
    //
    // @Parameter(names = "-crypto", description =
    // "Checks supported cipher suites and other crypto properties.")
    // protected boolean crypto;
    //
    // @Parameter(names = "-protocols", description =
    // "Checks supported TLS protocol versions.")
    // protected boolean supportedProtocols;
    //
    // @Parameter(names = "-cipher_suite_order", description =
    // "Checks whether the server supports cipher suite ordering.")
    // protected boolean cipherSuiteOrder;
    //
    // @Parameter(names = "-named_curves", description =
    // "Checks supported elliptic curves.")
    // protected boolean supportedNamedCurves;
    //
    // @Parameter(names = "-signature_hash_algorithms", description =
    // "Checks supported signature and hash algorithms.")
    // protected boolean supportedSignatureAndHashAlgorithms;
    //
    // @Parameter(names = "-attacks", description =
    // "Checks for potential vulnerabilities.")
    // protected boolean attacks;
    @Parameter(names = "-policy", description = "Checks the TLS configuration conformance against the provided (Botan-styled) policy.")
    protected String policy;

    public String getPolicy() {
        return policy;
    }

    public void setPolicy(String policy) {
        this.policy = policy;
    }

}
