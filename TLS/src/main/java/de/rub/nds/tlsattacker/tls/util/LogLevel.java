/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS.
 *
 * Copyright (C) 2015 Chair for Network and Data Security, Ruhr University
 * Bochum (juraj.somorovsky@rub.de)
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
package de.rub.nds.tlsattacker.tls.util;

import org.apache.logging.log4j.Level;

/**
 * 
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 */
public class LogLevel {

    /**
     * This log level is used to inform about important results of TLS
     * evaluations. For example, to present a final result of an executed
     * attack.
     */
    public static final Level CONSOLE_OUTPUT = Level.forName("CONSOLE_OUTPUT", 150);
}
