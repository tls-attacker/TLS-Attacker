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
import de.rub.nds.tlsattacker.tls.config.ClientCommandConfig;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTraceType;

/**
 * 
 * @author Philip Riese <philip.riese@rub.de>
 */
public class TripleHandshakeAttackCommandConfig extends ClientCommandConfig {

    public static final String ATTACK_COMMAND = "tripleHandshake";

    @Parameter(names = "-port", description = "ServerPort")
    protected String port = "4433";

    @Parameter(names = "-cert_secure_folder", description = "Cert secure folder on target server. Standard value = certsecure")
    protected String certSecure = "certsecure";

    @Parameter(names = "-session_ticket", description = "Enable if the server uses Session Tickets for Session Resumption")
    protected boolean sessionTicket = false;

    @Parameter(names = "-pause_after_FullHs", description = "Enable if there should be a pause between initial and Rehandshake")
    protected boolean pause = false;

    public TripleHandshakeAttackCommandConfig() {
	workflowTraceType = WorkflowTraceType.FULL_SERVER_RESPONSE;
    }

    public String getPort() {
	return port;
    }

    public void setPort(String port) {
	this.port = port;
    }

    public String getCertSecure() {
	return certSecure;
    }

    public void setCertSecure(String certSecure) {
	this.certSecure = certSecure;
    }

    public boolean isSessionTicket() {
	return sessionTicket;
    }

    public void setSessionTicket(boolean sessionTicket) {
	this.sessionTicket = sessionTicket;
    }

    public boolean isPause() {
	return pause;
    }

    public void setPause(boolean pause) {
	this.pause = pause;
    }
}
