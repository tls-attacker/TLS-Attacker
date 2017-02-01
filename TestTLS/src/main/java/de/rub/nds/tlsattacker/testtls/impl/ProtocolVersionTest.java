/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.testtls.impl;

import de.rub.nds.tlsattacker.testtls.config.TestServerConfig;
import de.rub.nds.tlsattacker.testtls.policy.TlsPeerProperties;
import de.rub.nds.tlsattacker.tls.config.ConfigHandler;
import de.rub.nds.tlsattacker.tls.constants.CipherSuite;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.workflow.TlsConfig;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * 
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 */
public class ProtocolVersionTest extends HandshakeTest {

    private final Set<ProtocolVersion> supportedProtocols;

    public ProtocolVersionTest(ConfigHandler configHandler, TestServerConfig serverConfig) {
        super(configHandler, serverConfig);
        supportedProtocols = new HashSet<>();
    }

    @Override
    public void startTests() {
        for (ProtocolVersion pv : ProtocolVersion.values()) {
            if (pv == ProtocolVersion.DTLS10 || pv == ProtocolVersion.DTLS12) {
                continue;
            }
            testCipherSuites(pv);
        }
        result = "\n Supported protocols: " + protocolsToString(supportedProtocols);
    }

    private void testCipherSuites(ProtocolVersion pv) {
        for (CipherSuite cs : CipherSuite.values()) {
            TlsConfig tlsConfig = configHandler.initialize(serverConfig);

            tlsConfig.setHighestProtocolVersion(pv);
            tlsConfig.setSupportedCiphersuites(Collections.singletonList(cs));
            boolean success = false;
            try {
                success = executeHandshake(tlsConfig);
            } catch (Exception ex) {
                LOGGER.info(ex.getLocalizedMessage());
                LOGGER.debug(ex.getLocalizedMessage(), ex);
            }
            if (success) {
                supportedProtocols.add(pv);
                return;
            }
        }
    }

    private String protocolsToString(Set<ProtocolVersion> protocols) {
        String output = "";
        for (ProtocolVersion pv : protocols) {
            output = output + pv.name() + " ";
        }
        return output;
    }

    public Set<ProtocolVersion> getSupportedProtocols() {
        return supportedProtocols;
    }

    @Override
    public void fillTlsPeerProperties(TlsPeerProperties properties) {
        properties.setProtocolVersions(supportedProtocols);
    }
}
