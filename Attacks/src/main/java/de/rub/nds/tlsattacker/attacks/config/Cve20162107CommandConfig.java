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
import de.rub.nds.tlsattacker.core.config.delegate.CiphersuiteDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.ClientDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.StarttlsDelegate;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

/**
 *
 */
public class Cve20162107CommandConfig extends AttackConfig {

    /**
     *
     */
    public static final String ATTACK_COMMAND = "cve20162107";
    @Parameter(names = "-versions", description = "Protocol versions to test")
    private List<ProtocolVersion> versions;

    @ParametersDelegate
    private ClientDelegate clientDelegate;
    @ParametersDelegate
    private CiphersuiteDelegate cipherSuiteDelegate;
    @ParametersDelegate
    private StarttlsDelegate starttlsDelegate;

    /**
     *
     * @param delegate
     */
    public Cve20162107CommandConfig(GeneralDelegate delegate) {
        super(delegate);
        versions = new LinkedList<>();
        versions.add(ProtocolVersion.TLS10);
        versions.add(ProtocolVersion.TLS11);
        versions.add(ProtocolVersion.TLS12);
        clientDelegate = new ClientDelegate();
        cipherSuiteDelegate = new CiphersuiteDelegate();
        starttlsDelegate = new StarttlsDelegate();
        addDelegate(clientDelegate);
        addDelegate(cipherSuiteDelegate);
        addDelegate(starttlsDelegate);

    }

    /**
     *
     * @return
     */
    public List<ProtocolVersion> getVersions() {
        return Collections.unmodifiableList(versions);
    }

    /**
     *
     * @param versions
     */
    public void setVersions(List<ProtocolVersion> versions) {
        this.versions = versions;
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
        config.setAddRenegotiationInfoExtension(true);
        config.setAddServerNameIndicationExtension(true);
        config.setAddSignatureAndHashAlgorithmsExtension(true);
        config.setQuickReceive(true);
        config.setStopActionsAfterFatal(true);
        config.setStopReceivingAfterFatal(true);
        config.setEarlyStop(true);
        if (cipherSuiteDelegate.getCipherSuites() == null) {
            List<CipherSuite> cipherSuites = new LinkedList<>();
            cipherSuites.add(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA);
            cipherSuites.add(CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA);
            cipherSuites.add(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256);
            cipherSuites.add(CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA);
            cipherSuites.add(CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256);
            config.setDefaultClientSupportedCiphersuites(cipherSuites);
        }
        for (CipherSuite suite : config.getDefaultClientSupportedCiphersuites()) {
            if (!suite.isCBC()) {
                throw new ConfigurationException("This attack only works with CBC Ciphersuites");
            }

        }
        return config;
    }
}
