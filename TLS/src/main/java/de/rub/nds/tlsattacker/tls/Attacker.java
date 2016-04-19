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
package de.rub.nds.tlsattacker.tls;

import de.rub.nds.tlsattacker.tls.config.CommandConfig;
import de.rub.nds.tlsattacker.tls.config.ConfigHandler;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import java.util.LinkedList;
import java.util.List;

/**
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 * @param <Config>
 */
public abstract class Attacker<Config extends CommandConfig> {

    protected Config config;

    /**
     * Tls Contexts stored for logging purposes
     */
    protected List<TlsContext> tlsContexts;

    public Attacker(Config config) {
	this.config = config;
	tlsContexts = new LinkedList<>();
    }

    /**
     * Executes a given attack
     * 
     * @param configHandler
     */
    public abstract void executeAttack(ConfigHandler configHandler);

    public Config getConfig() {
	return config;
    }

    public void setConfig(Config config) {
	this.config = config;
    }

    public List<TlsContext> getTlsContexts() {
	return tlsContexts;
    }

    public void setTlsContexts(List<TlsContext> tlsContexts) {
	this.tlsContexts = tlsContexts;
    }
}
