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
import com.beust.jcommander.ParametersDelegate;
import de.rub.nds.tlsattacker.tls.config.TLSDelegateConfig;
import de.rub.nds.tlsattacker.tls.config.delegate.ClientDelegate;
import de.rub.nds.tlsattacker.tls.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.tls.config.delegate.HostnameExtensionDelegate;

/**
 * Configuration for testing TLS server capabilities. By now, per default all
 * the checks are performed. In the future, more fine granular tests can be
 * executed, as is the case in testssl.sh. See also the commented out variables.
 *
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 */
public class TestServerConfig extends TLSDelegateConfig {

    public static final String COMMAND = "testtls_server";

    @Parameter(names = "-policy", description = "Checks the TLS configuration conformance against the provided (Botan-styled) policy.")
    private String policy;

    @ParametersDelegate
    private final ClientDelegate clientDelegate;
    @ParametersDelegate
    private final HostnameExtensionDelegate hostnameDelegate;

    public TestServerConfig(GeneralDelegate delegate) {
        super(delegate);
        clientDelegate = new ClientDelegate();
        hostnameDelegate = new HostnameExtensionDelegate();
        addDelegate(hostnameDelegate);
        addDelegate(clientDelegate);
    }

    public String getPolicy() {
        return policy;
    }

    public void setPolicy(String policy) {
        this.policy = policy;
    }

}
