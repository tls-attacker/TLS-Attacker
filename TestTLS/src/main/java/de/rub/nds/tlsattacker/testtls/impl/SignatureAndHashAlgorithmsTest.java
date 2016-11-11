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
import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.constants.HashAlgorithm;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.constants.SignatureAlgorithm;
import de.rub.nds.tlsattacker.tls.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ServerKeyExchangeMessage;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Tests the acceptance of the Signature and Hash Algorithm extension. See
 * https://tools.ietf.org/html/rfc5246#section-7.4.1.4.1
 * 
 * We just send different values in the extension with all the supported
 * extension values. If the server responds with a ServerHello message, it must
 * support the proposed signature and hash algorithms.
 * 
 * This extension is only fully supported in TLS 1.2. In previous versions, it
 * can be ignored if the server does not understand it.
 * 
 * From https://tools.ietf.org/html/rfc5246#section-7.4.3 (describing
 * ServerKeyExchange message): "If the client has offered the
 * "signature_algorithms" extension, the signature algorithm and hash algorithm
 * MUST be a pair listed in that extension. Note that there is a possibility for
 * inconsistencies here. For instance, the client might offer DHE_DSS key
 * exchange but omit any DSA pairs from its "signature_algorithms" extension. In
 * order to negotiate correctly, the server MUST check any candidate cipher
 * suites against the "signature_algorithms" extension before selecting them.
 * This is somewhat inelegant but is a compromise designed to minimize changes
 * to the original cipher suite design."
 * 
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 */
public class SignatureAndHashAlgorithmsTest extends HandshakeTest {

    private final Set<SignatureAndHashAlgorithm> signatureAndHashAlgorithms;

    private final HashMap<ProtocolVersion, List<CipherSuite>> supportedCipherSuites;

    public SignatureAndHashAlgorithmsTest(ConfigHandler configHandler, TestServerConfig serverConfig,
            HashMap<ProtocolVersion, List<CipherSuite>> supportedCipherSuites) {
        super(configHandler, serverConfig);
        this.signatureAndHashAlgorithms = new HashSet<>();
        this.supportedCipherSuites = supportedCipherSuites;
    }

    @Override
    public void startTests() {
        // This extension is only supported in TLS 1.2
        // (see https://tools.ietf.org/html/rfc5246#section-7.4.1.4.1)
        if (!supportedCipherSuites.get(ProtocolVersion.TLS12).isEmpty()) {
            testSupportedSignatureAndHashAlgorithms(ProtocolVersion.TLS12);
        }
        result = "\n Supported signature and hash algorithms: "
                + signatureAndHashAlgorithmsToString(signatureAndHashAlgorithms);
    }

    private void testSupportedSignatureAndHashAlgorithms(ProtocolVersion pv) {
        for (SignatureAndHashAlgorithm algorithm : SignatureAndHashAlgorithm.values()) {
            serverConfig.setProtocolVersion(pv);
            serverConfig.setCipherSuites(supportedCipherSuites.get(pv));
            serverConfig.setSignatureAndHashAlgorithms(Collections.singletonList(algorithm));
            boolean success = false;
            try {
                success = executeHandshake();
            } catch (Exception ex) {
                LOGGER.info(ex.getLocalizedMessage());
                LOGGER.debug(ex.getLocalizedMessage(), ex);
            }
            if (success) {
                signatureAndHashAlgorithms.add(algorithm);
                if (lastTlsContext.getWorkflowTrace()
                        .getActuallyRecievedHandshakeMessagesOfType(HandshakeMessageType.SERVER_KEY_EXCHANGE).get(0) != null) {
                    ServerKeyExchangeMessage skm = (ServerKeyExchangeMessage) lastTlsContext.getWorkflowTrace()
                            .getActuallyRecievedHandshakeMessagesOfType(HandshakeMessageType.SERVER_KEY_EXCHANGE)
                            .get(0);
                    Byte sa = skm.getSignatureAlgorithm().getValue();
                    Byte ha = skm.getHashAlgorithm().getValue();
                    signatureAndHashAlgorithms.add(new SignatureAndHashAlgorithm(new byte[] { ha, sa }));
                }
            }
        }
    }

    private String signatureAndHashAlgorithmsToString(Set<SignatureAndHashAlgorithm> algorithms) {
        String output = "";
        for (SignatureAndHashAlgorithm sha : algorithms) {
            output = output + sha.getSignatureAlgorithm() + "-" + sha.getHashAlgorithm() + " ";
        }
        return output;
    }

    @Override
    public void fillTlsPeerProperties(TlsPeerProperties properties) {
        properties.setSignatureAndHashAlgorithms(signatureAndHashAlgorithms);
    }
}
