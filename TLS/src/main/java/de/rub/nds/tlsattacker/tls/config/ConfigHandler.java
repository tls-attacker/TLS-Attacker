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
package de.rub.nds.tlsattacker.tls.config;

import com.beust.jcommander.JCommander;
import de.rub.nds.tlsattacker.tls.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import java.lang.reflect.Field;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.config.Configuration;
import org.apache.logging.log4j.core.config.LoggerConfig;

/**
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public abstract class ConfigHandler {

    public void initializeGeneralConfig(GeneralConfig config) {
	LoggerContext ctx = (LoggerContext) LogManager.getContext(false);
	Configuration ctxConfig = ctx.getConfiguration();
	LoggerConfig loggerConfig = ctxConfig.getLoggerConfig(LogManager.ROOT_LOGGER_NAME);
	if (config.isDebug()) {
	    loggerConfig.setLevel(Level.DEBUG);
	    ctx.updateLoggers();
	} else if (config.isQuiet()) {
	    loggerConfig.setLevel(Level.OFF);
	    ctx.updateLoggers();
	} else if (config.getLogLevel() != null) {
	    loggerConfig.setLevel(config.getLogLevel());
	    ctx.updateLoggers();
	}

	// remove stupid Oracle JDK security restriction (otherwise, it is not
	// possible to use strong crypto with Oracle JDK)
	try {
	    Field field = Class.forName("javax.crypto.JceSecurity").getDeclaredField("isRestricted");
	    field.setAccessible(true);
	    field.set(null, java.lang.Boolean.FALSE);
	} catch (ClassNotFoundException | IllegalAccessException | IllegalArgumentException | NoSuchFieldException
		| SecurityException ex) {
	    throw new ConfigurationException("Not possible to use unrestricted policy in Oracle JDK", ex);
	}
    }

    public boolean printHelpForCommand(JCommander jc, CommandConfig config) {
	if (config.isHelp()) {
	    jc.usage(jc.getParsedCommand());
	    return true;
	}
	return false;
    }

    public abstract TransportHandler initializeTransportHandler(CommandConfig config) throws ConfigurationException;

    public abstract TlsContext initializeTlsContext(CommandConfig config);

    public abstract WorkflowExecutor initializeWorkflowExecutor(TransportHandler transportHandler, TlsContext tlsContext);
}
