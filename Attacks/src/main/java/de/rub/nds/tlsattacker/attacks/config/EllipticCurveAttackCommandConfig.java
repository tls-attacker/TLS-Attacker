/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS.
 *
 * Copyright (C) 2015 Chair for Network and Data Security,
 *                    Ruhr University Bochum
 *                    (juraj.somorovsky@rub.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.rub.nds.tlsattacker.attacks.config;

import com.beust.jcommander.Parameter;
import de.rub.nds.tlsattacker.attacks.ec.ICEAttacker;
import de.rub.nds.tlsattacker.tls.config.ClientCommandConfig;
import de.rub.nds.tlsattacker.tls.constants.CipherSuite;
import de.rub.nds.tlsattacker.tls.constants.NamedCurve;
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
