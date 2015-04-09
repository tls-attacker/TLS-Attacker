package de.rub.nds.tlsattacker.attacks.config;

import com.beust.jcommander.Parameter;
import de.rub.nds.tlsattacker.attacks.ec.ICEAttacker;
import de.rub.nds.tlsattacker.tls.config.ClientCommandConfig;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.CipherSuite;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.NamedCurve;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTraceType;

/**
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class EllipticCurveAttackCommandConfig extends ClientCommandConfig {

    public static final String ATTACK_COMMAND = "elliptic";

    @Parameter(names = "-additional_equations", description = "Additional equations used when attacking Oracle JSSE server (needed because of a faulty JSSE implementation).")
    protected int additionalEquations;

    @Parameter(names = "-server_type", description = "Allows to switch between a normal vulnerable server type and an Oracle server type (for oracle a slightly different algorithm is needed).")
    protected ICEAttacker.ServerType serverType;

    public EllipticCurveAttackCommandConfig() {
	cipherSuites.clear();
	cipherSuites.add(CipherSuite.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA);
	cipherSuites.add(CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA);
	namedCurves.clear();
	namedCurves.add(NamedCurve.SECP256R1);
	workflowTraceType = WorkflowTraceType.HANDSHAKE;
	additionalEquations = 3;
	serverType = ICEAttacker.ServerType.NORMAL;
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

}
