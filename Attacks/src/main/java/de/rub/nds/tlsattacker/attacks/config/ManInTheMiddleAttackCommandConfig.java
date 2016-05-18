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

/**
 * 
 * @author Philip Riese <philip.riese@rub.de>
 */
public class ManInTheMiddleAttackCommandConfig extends ClientCommandConfig {

    public static final String ATTACK_COMMAND = "mitm";

    @Parameter(names = "-port", description = "ServerPort")
    protected String port = "4433";

    @Parameter(names = "-modify", description = "Modify the whole Workflow ")
    protected boolean modify = false;

    public String getPort() {
	return port;
    }

    public void setPort(String port) {
	this.port = port;
    }

    public boolean isModify() {
	return modify;
    }

    public void setModify(boolean modify) {
	this.modify = modify;
    }
}
