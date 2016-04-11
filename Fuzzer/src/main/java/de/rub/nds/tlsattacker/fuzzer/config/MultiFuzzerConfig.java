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
package de.rub.nds.tlsattacker.fuzzer.config;

import com.beust.jcommander.Parameter;

/**
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class MultiFuzzerConfig {

    public static final String ATTACK_COMMAND = "clever_multi_fuzzer";

    @Parameter(names = { "-h", "-help" }, help = true, description = "Prints help")
    protected boolean help;

    @Parameter(names = "-startup_command_file", required = true, description = "XML file that is used for starting the server and the fuzzer.")
    String startupCommandFile;

    public MultiFuzzerConfig() {

    }

    public String getStartupCommandFile() {
	return startupCommandFile;
    }

    public void setStartupCommandFile(String startupCommandFile) {
	this.startupCommandFile = startupCommandFile;
    }

    public boolean isHelp() {
	return help;
    }

    public void setHelp(boolean help) {
	this.help = help;
    }
}
