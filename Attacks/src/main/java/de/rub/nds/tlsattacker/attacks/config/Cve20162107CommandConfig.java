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
import de.rub.nds.tlsattacker.tls.config.delegate.CiphersuiteDelegate;
import de.rub.nds.tlsattacker.tls.config.delegate.ClientDelegate;
import de.rub.nds.tlsattacker.tls.constants.CipherSuite;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.workflow.TlsConfig;
import java.util.LinkedList;
import java.util.List;

/**
 *
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class Cve20162107CommandConfig extends TLSDelegateConfig {

    public static final String ATTACK_COMMAND = "cve20162107";
    @Parameter(names = "-versions", description = "Protocol versions to test")
    private List<ProtocolVersion> versions;
    
    @ParametersDelegate
    private ClientDelegate clientDelegate;
    @ParametersDelegate
    private CiphersuiteDelegate cipherSuiteDelegate;
    
    public Cve20162107CommandConfig() {
        versions = new LinkedList<>();
        versions.add(ProtocolVersion.TLS10);
        versions.add(ProtocolVersion.TLS11);
        versions.add(ProtocolVersion.TLS12);
        clientDelegate = new ClientDelegate();
        cipherSuiteDelegate = new CiphersuiteDelegate();
        addDelegate(clientDelegate);
        addDelegate(cipherSuiteDelegate);
    }
    
    public List<ProtocolVersion> getVersions() {
        return versions;
    }

    public void setVersions(List<ProtocolVersion> versions) {
        this.versions = versions;
    }

    @Override
    public TlsConfig createConfig() {
        TlsConfig config = super.createConfig();
        //TODO
        config.setSupportedCiphersuites(new LinkedList<CipherSuite>()); 
        return config;
    }
}
