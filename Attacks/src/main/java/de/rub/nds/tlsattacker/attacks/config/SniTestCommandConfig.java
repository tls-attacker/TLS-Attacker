/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.config;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParametersDelegate;
import de.rub.nds.tlsattacker.tls.config.TLSDelegateConfig;
import de.rub.nds.tlsattacker.tls.config.delegate.ClientDelegate;
import de.rub.nds.tlsattacker.tls.constants.CipherSuite;
import de.rub.nds.tlsattacker.tls.workflow.TlsConfig;
import java.util.LinkedList;
import java.util.List;

/**
 *
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class SniTestCommandConfig extends TLSDelegateConfig {

    public static final String ATTACK_COMMAND = "sni_test";
    @ParametersDelegate
    private final ClientDelegate clientDelegate;

    @Parameter(names = "-server_name2", description = "Servername for HostName TLS extension, used in the second ClientHello message.")
    protected String serverName2;

    public SniTestCommandConfig() {
        clientDelegate = new ClientDelegate();
        addDelegate(clientDelegate);
    }

    public String getServerName2() {
        return serverName2;
    }

    public void setServerName2(String serverName2) {
        this.serverName2 = serverName2;
    }

    @Override
    public TlsConfig createConfig() {
        TlsConfig config = super.createConfig();
        List<CipherSuite> cipherSuites = new LinkedList<>();
        cipherSuites.add(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA);
        cipherSuites.add(CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA);
        cipherSuites.add(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256);
        cipherSuites.add(CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256);
        return config;
    }
}
