/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.config;

import com.beust.jcommander.JCommander;
import de.rub.nds.tlsattacker.tls.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import java.lang.reflect.Field;
import java.security.Provider;
import java.security.Security;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.config.Configuration;
import org.apache.logging.log4j.core.config.LoggerConfig;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public abstract class ConfigHandler {

    static final Logger LOGGER = LogManager.getLogger(ConfigHandler.class);

    /**
     * Initializes TLS Attacker according to the config file. In addition, it
     * adds the Bouncy Castle provider and removes the PKCS#11 security provider
     * since there are some problems when handling ECC.
     * 
     * @param config
     */
    public void initialize(GeneralConfig config) {

        // ECC does not work properly in the NSS provider
        Security.removeProvider("SunPKCS11-NSS");
        Security.addProvider(new BouncyCastleProvider());
        LOGGER.debug("Using the following security providers");
        for (Provider p : Security.getProviders()) {
            LOGGER.debug("Provider {}, version, {}", p.getName(), p.getVersion());
        }

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
            if (field.getBoolean(null)) {
                field.set(null, java.lang.Boolean.FALSE);
            }
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
