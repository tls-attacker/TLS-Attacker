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
import static de.rub.nds.tlsattacker.testtls.impl.CryptoTest.LOGGER;
import de.rub.nds.tlsattacker.testtls.policy.TlsPeerProperties;
import de.rub.nds.tlsattacker.tls.config.ConfigHandler;
import de.rub.nds.tlsattacker.tls.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.tls.constants.CipherSuite;
import de.rub.nds.tlsattacker.tls.constants.KeyExchangeAlgorithm;
import de.rub.nds.tlsattacker.tls.constants.NamedCurve;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * 
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 */
public class NamedCurvesTest extends HandshakeTest {

    private final Set<NamedCurve> supportedCurves;

    private final HashMap<ProtocolVersion, List<CipherSuite>> supportedCipherSuites;

    /**
     * Size of EC ephemeral keys provided by the server
     */
    private int minimumECDHGroupSize;

    public NamedCurvesTest(ConfigHandler configHandler, TestServerConfig serverConfig,
            HashMap<ProtocolVersion, List<CipherSuite>> supportedCipherSuites) {
        super(configHandler, serverConfig);
        this.supportedCurves = new HashSet<>();
        this.supportedCipherSuites = supportedCipherSuites;
    }

    @Override
    public void startTests() {
        // we execute this test for every protocol since different protocols
        // can contain different curves support
        for (ProtocolVersion pv : supportedCipherSuites.keySet()) {
            testSupportedCurves(pv);
        }
        result = "\n Supported named curves: " + namedCurvesToString(supportedCurves);
        result += "\n Minimum ECDH group size: " + minimumECDHGroupSize;
    }

    private void testSupportedCurves(ProtocolVersion pv) {
        for (CipherSuite cs : supportedCipherSuites.get(pv)) {
            if (AlgorithmResolver.getKeyExchangeAlgorithm(cs) == KeyExchangeAlgorithm.EC_DIFFIE_HELLMAN) {
                testSupportedCurves(pv, cs);
                return;
            }
        }
    }

    private void testSupportedCurves(ProtocolVersion pv, CipherSuite cs) {
        for (NamedCurve nc : NamedCurve.values()) {
            serverConfig.setProtocolVersion(pv);
            serverConfig.setCipherSuites(Collections.singletonList(cs));
            serverConfig.setNamedCurves(Collections.singletonList(nc));
            boolean success = false;
            try {
                success = executeHandshake();
            } catch (Exception ex) {
                LOGGER.info(ex.getLocalizedMessage());
                LOGGER.debug(ex.getLocalizedMessage(), ex);
            }
            if (success) {
                supportedCurves.add(nc);
                if (lastTlsContext.getEcContext().getServerPublicKeyParameters() != null) {
                    LOGGER.info("EC parameter public key size: {}", lastTlsContext.getEcContext()
                            .getServerPublicKeyParameters().getParameters().getCurve().getFieldSize());
                    int groupSize = lastTlsContext.getEcContext().getServerPublicKeyParameters().getParameters()
                            .getCurve().getFieldSize();
                    if (minimumECDHGroupSize == 0 || groupSize < minimumECDHGroupSize) {
                        minimumECDHGroupSize = groupSize;
                    }
                }
            }
        }
    }

    private String namedCurvesToString(Set<NamedCurve> namedCurves) {
        String output = "";
        for (NamedCurve nc : namedCurves) {
            output = output + nc.name() + " ";
        }
        return output;
    }

    @Override
    public void fillTlsPeerProperties(TlsPeerProperties properties) {
        properties.setNamedCurves(supportedCurves);
        properties.setMinimumEcdhGroupSize(minimumECDHGroupSize);
    }
}
