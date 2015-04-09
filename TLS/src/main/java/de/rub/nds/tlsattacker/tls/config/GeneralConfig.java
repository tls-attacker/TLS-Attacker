/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS.
 *
 * Copyright (C) 2015 Juraj Somorovsky
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package de.rub.nds.tlsattacker.tls.config;

import de.rub.nds.tlsattacker.tls.config.converters.LogLevelConverter;
import com.beust.jcommander.Parameter;
import org.apache.logging.log4j.Level;

/**
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class GeneralConfig {
    @Parameter(names = { "-h", "-help" }, help = true, description = "Prints usage for all the existing commands.")
    private boolean help;

    @Parameter(names = "-debug", description = "Show extra debug output (sets logLevel to DEBUG)")
    private boolean debug;

    @Parameter(names = "-quiet", description = "No output (sets logLevel to NONE)")
    private boolean quiet;

    @Parameter(names = "-loglevel", description = "Set Log4j log level.", converter = LogLevelConverter.class)
    private Level logLevel;

    public boolean isHelp() {
	return help;
    }

    public void setHelp(boolean help) {
	this.help = help;
    }

    public boolean isDebug() {
	return debug;
    }

    public void setDebug(boolean debug) {
	this.debug = debug;
    }

    public boolean isQuiet() {
	return quiet;
    }

    public void setQuiet(boolean quiet) {
	this.quiet = quiet;
    }

    public Level getLogLevel() {
	return logLevel;
    }

    public void setLogLevel(Level logLevel) {
	this.logLevel = logLevel;
    }
}
