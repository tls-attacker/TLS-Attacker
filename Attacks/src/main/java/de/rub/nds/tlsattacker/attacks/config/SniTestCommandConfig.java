/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.config;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParametersDelegate;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.delegate.ClientDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import java.util.LinkedList;
import java.util.List;

/**
 *
 * @author robert
 */
public class SniTestCommandConfig extends AttackConfig {

    /**
     *
     */
    public static final String ATTACK_COMMAND = "sni_test";
    @ParametersDelegate
    private ClientDelegate clientDelegate;

    @Parameter(names = "-server_name2", description = "Servername for HostName TLS extension, used in the second ClientHello message.")
    private String serverName2;

    /**
     *
     * @param delegate
     */
    public SniTestCommandConfig(GeneralDelegate delegate) {
        super(delegate);
        clientDelegate = new ClientDelegate();
        addDelegate(clientDelegate);
    }

    /**
     *
     * @return
     */
    public String getServerName2() {
        return serverName2;
    }

    /**
     *
     * @param serverName2
     */
    public void setServerName2(String serverName2) {
        this.serverName2 = serverName2;
    }

    /**
     *
     * @return
     */
    @Override
    public boolean isExecuteAttack() {
        return false;
    }

    /**
     *
     * @return
     */
    @Override
    public Config createConfig() {
        Config config = super.createConfig();
        List<CipherSuite> cipherSuites = new LinkedList<>();
        cipherSuites.add(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA);
        cipherSuites.add(CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA);
        cipherSuites.add(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256);
        cipherSuites.add(CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256);
        return config;
    }
}
