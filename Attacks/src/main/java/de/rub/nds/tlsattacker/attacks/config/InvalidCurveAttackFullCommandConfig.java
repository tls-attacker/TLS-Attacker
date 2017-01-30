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
import de.rub.nds.tlsattacker.attacks.ec.ICEAttacker;
import de.rub.nds.tlsattacker.tls.config.TLSDelegateConfig;
import de.rub.nds.tlsattacker.tls.constants.CipherSuite;
import de.rub.nds.tlsattacker.tls.constants.NamedCurve;
import de.rub.nds.tlsattacker.tls.workflow.TlsConfig;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTraceType;
import java.util.LinkedList;
import java.util.List;

/**
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class InvalidCurveAttackFullCommandConfig extends TLSDelegateConfig {

    public static final String ATTACK_COMMAND = "invalid_curve_full";

    @Parameter(names = "-additional_equations", description = "Additional equations used when attacking Oracle JSSE server (needed because of a faulty JSSE implementation).")
    protected int additionalEquations = 3;

    @Parameter(names = "-server_type", description = "Allows to switch between a normal vulnerable server type and an Oracle server type (for oracle a slightly different algorithm is needed).")
    protected ICEAttacker.ServerType serverType = ICEAttacker.ServerType.NORMAL;

    public InvalidCurveAttackFullCommandConfig() {
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
        namedCurves.add(NamedCurve.SECP256R1);
        config.setNamedCurves(namedCurves);
        config.setWorkflowTraceType(WorkflowTraceType.HANDSHAKE);
        return config;
    }

}
