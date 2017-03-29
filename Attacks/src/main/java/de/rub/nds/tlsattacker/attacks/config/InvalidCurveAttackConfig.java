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
import de.rub.nds.tlsattacker.attacks.ec.ICEAttacker;
import de.rub.nds.tlsattacker.tls.config.TLSDelegateConfig;
import de.rub.nds.tlsattacker.tls.config.converters.BigIntegerConverter;
import de.rub.nds.tlsattacker.tls.config.converters.NamedCurveConverter;
import de.rub.nds.tlsattacker.tls.config.delegate.CiphersuiteDelegate;
import de.rub.nds.tlsattacker.tls.config.delegate.ClientDelegate;
import de.rub.nds.tlsattacker.tls.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.tls.config.delegate.HostnameExtensionDelegate;
import de.rub.nds.tlsattacker.tls.config.delegate.ProtocolVersionDelegate;
import de.rub.nds.tlsattacker.tls.constants.CipherSuite;
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
public class InvalidCurveAttackConfig extends AttackConfig {

    public static final String ATTACK_COMMAND = "invalid_curve";

    @Parameter(names = "-named_curve", description = "Named curve to be used", converter = NamedCurveConverter.class)
    private NamedCurve namedCurve = NamedCurve.SECP256R1;

    @Parameter(names = "-additional_equations", description = "Additional equations used when attacking Oracle JSSE server (needed because of a faulty JSSE implementation).")
    private int additionalEquations = 3;

    @Parameter(names = "-server_type", description = "Allows to switch between a normal vulnerable server type and an Oracle server type (for oracle a slightly different algorithm is needed).")
    private ICEAttacker.ServerType serverType = ICEAttacker.ServerType.NORMAL;

    /**
     * EC field size, currently set to 32, works for curves with 256 bits!
     */
    @Parameter(names = "-curve_field_size", description = "Curve field size. 32 works for 256bits.")
    private int curveFieldSize = 32;

    @Parameter(names = "-protocol_flows", description = "Number of Protocol flows")
    private int protocolFlows = 15;

    // These are for scanning only
    @Parameter(names = "-premaster_secret", description = "Premaster Secret String (use 0x at the beginning for a hex value)", hidden = true, converter = BigIntegerConverter.class)
    private BigInteger premasterSecret = new BigInteger(
            "b70bf043c144935756f8f4578c369cf960ee510a5a0f90e93a373a21f0d1397f", 16);

    @Parameter(names = "-public_point_base_x", hidden = true, description = "Public key point coordinate X sent to the server (use 0x at the beginning for a hex value)", converter = BigIntegerConverter.class)
    private BigInteger publicPointBaseX = new BigInteger(
            "b70bf043c144935756f8f4578c369cf960ee510a5a0f90e93a373a21f0d1397f", 16);

    @Parameter(names = "-public_point_base_y", hidden = true, description = "Public key point coordinate Y sent to the server (use 0x at the beginning for a hex value)", converter = BigIntegerConverter.class)
    private BigInteger publicPointBaseY = new BigInteger(
            "4a2e0ded57a5156bb82eb4314c37fd4155395a7e51988af289cce531b9c17192", 16);

    @ParametersDelegate
    private final ClientDelegate clientDelegate;

    @ParametersDelegate
    private final HostnameExtensionDelegate hostnameExtensionDelegate;

    @ParametersDelegate
    private final CiphersuiteDelegate ciphersuiteDelegate;

    @ParametersDelegate
    private final ProtocolVersionDelegate protocolVersionDelegate;

    public InvalidCurveAttackConfig(GeneralDelegate delegate) {
        super(delegate);
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

    public NamedCurve getNamedCurve() {
        return namedCurve;
    }

    public void setNamedCurve(NamedCurve namedCurve) {
        this.namedCurve = namedCurve;
    }

    public int getCurveFieldSize() {
        return curveFieldSize;
    }

    public void setCurveFieldSize(int curveFieldSize) {
        this.curveFieldSize = curveFieldSize;
    }

    public int getProtocolFlows() {
        return protocolFlows;
    }

    public void setProtocolFlows(int protocolFlows) {
        this.protocolFlows = protocolFlows;
    }

    public int getAdditionalEquations() {
        return additionalEquations;
    }

    public void setAdditionalEquations(int additionalEquations) {
        this.additionalEquations = additionalEquations;
    }

    public ICEAttacker.ServerType getServerType() {
        return serverType;
    }

    public void setServerType(ICEAttacker.ServerType serverType) {
        this.serverType = serverType;
    }

    @Override
    public TlsConfig createConfig() {
        TlsConfig config = super.createConfig();
        List<CipherSuite> cipherSuites = new LinkedList<>();
        cipherSuites.add(CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA);
        cipherSuites.add(CipherSuite.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA);
        config.setSupportedCiphersuites(cipherSuites);
        List<NamedCurve> namedCurves = new LinkedList<>();
        namedCurves.add(namedCurve);
        config.setNamedCurves(namedCurves);
        config.setWorkflowTraceType(WorkflowTraceType.HANDSHAKE);
        return config;
    }

}
