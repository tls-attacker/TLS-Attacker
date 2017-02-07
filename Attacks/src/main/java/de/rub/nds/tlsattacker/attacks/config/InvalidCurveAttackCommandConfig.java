/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.config;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParametersDelegate;
import de.rub.nds.tlsattacker.tls.config.TLSDelegateConfig;
import de.rub.nds.tlsattacker.tls.config.converters.BigIntegerConverter;
import de.rub.nds.tlsattacker.tls.config.delegate.CiphersuiteDelegate;
import de.rub.nds.tlsattacker.tls.config.delegate.ClientDelegate;
import de.rub.nds.tlsattacker.tls.config.delegate.HostnameExtensionDelegate;
import de.rub.nds.tlsattacker.tls.config.delegate.ProtocolVersionDelegate;
import de.rub.nds.tlsattacker.tls.constants.CipherSuite;
import de.rub.nds.tlsattacker.tls.constants.HeartbeatMode;
import de.rub.nds.tlsattacker.tls.constants.NamedCurve;
import de.rub.nds.tlsattacker.tls.workflow.TlsConfig;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTraceType;
import java.math.BigInteger;
import java.util.LinkedList;
import java.util.List;

/**
 *
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class InvalidCurveAttackCommandConfig extends TLSDelegateConfig {

    public static final String ATTACK_COMMAND = "invalid_curve";

    @Parameter(names = "-premaster_secret", description = "Premaster Secret String (use 0x at the beginning for a hex value)", converter = BigIntegerConverter.class)
    BigInteger premasterSecret;

    @Parameter(names = "-public_point_base_x", description = "Public key point coordinate X sent to the server (use 0x at the beginning for a hex value)", converter = BigIntegerConverter.class)
    BigInteger publicPointBaseX;

    @Parameter(names = "-public_point_base_y", description = "Public key point coordinate Y sent to the server (use 0x at the beginning for a hex value)", converter = BigIntegerConverter.class)
    BigInteger publicPointBaseY;

    @ParametersDelegate
    private ClientDelegate clientDelegate;
    @ParametersDelegate
    private HostnameExtensionDelegate hostnameExtensionDelegate;
    @ParametersDelegate
    private CiphersuiteDelegate ciphersuiteDelegate;
    @ParametersDelegate
    private ProtocolVersionDelegate protocolVersionDelegate;

    public InvalidCurveAttackCommandConfig() {
        clientDelegate = new ClientDelegate();
        hostnameExtensionDelegate = new HostnameExtensionDelegate();
        ciphersuiteDelegate = new CiphersuiteDelegate();
        protocolVersionDelegate = new ProtocolVersionDelegate();
        addDelegate(clientDelegate);
        addDelegate(hostnameExtensionDelegate);
        addDelegate(ciphersuiteDelegate);
        addDelegate(protocolVersionDelegate);
    }

    public BigInteger getPremasterSecret() {
        return premasterSecret;
    }

    public void setPremasterSecret(BigInteger premasterSecret) {
        this.premasterSecret = premasterSecret;
    }

    public BigInteger getPublicPointBaseX() {
        return publicPointBaseX;
    }

    public void setPublicPointBaseX(BigInteger publicPointBaseX) {
        this.publicPointBaseX = publicPointBaseX;
    }

    public BigInteger getPublicPointBaseY() {
        return publicPointBaseY;
    }

    public void setPublicPointBaseY(BigInteger publicPointBaseY) {
        this.publicPointBaseY = publicPointBaseY;
    }

    @Override
    public TlsConfig createConfig() {
        TlsConfig config = super.createConfig();
        List<CipherSuite> cipherSuites = new LinkedList<>();
        cipherSuites.add(CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA);
        cipherSuites.add(CipherSuite.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA);
        config.setSupportedCiphersuites(cipherSuites);
        List<NamedCurve> namedCurves = new LinkedList<>();
        namedCurves.add(NamedCurve.SECP256R1);
        config.setNamedCurves(namedCurves);
        config.setWorkflowTraceType(WorkflowTraceType.HANDSHAKE);
        return config;
    }

}
