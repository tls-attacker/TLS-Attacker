/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.config.delegate;

import com.beust.jcommander.Parameter;
import de.rub.nds.tlsattacker.tls.config.converters.LogLevelConverter;
import de.rub.nds.tlsattacker.tls.workflow.TlsConfig;
import de.rub.nds.tlsattacker.util.UnlimitedStrengthEnabler;
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
public class GeneralDelegate extends Delegate {

    static final Logger LOGGER = LogManager.getLogger("Config");

    @Parameter(names = { "-h", "-help" }, help = true, description = "Prints usage for all the existing commands.")
    private boolean help;

    @Parameter(names = "-debug", description = "Show extra debug output (sets logLevel to DEBUG)")
    private boolean debug;

    @Parameter(names = "-quiet", description = "No output (sets logLevel to NONE)")
    private boolean quiet;

    @Parameter(names = "-loglevel", description = "Set Log4j log level.", converter = LogLevelConverter.class)
    private Level logLevel = Level.INFO;

    public GeneralDelegate() {
    }

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

    @Override
    public void applyDelegate(TlsConfig config) {
        LoggerContext ctx = (LoggerContext) LogManager.getContext(false);
        Configuration ctxConfig = ctx.getConfiguration();
        LoggerConfig loggerConfig = ctxConfig.getLoggerConfig(LogManager.ROOT_LOGGER_NAME);
        if (isDebug()) {
            loggerConfig.setLevel(Level.DEBUG);
            ctx.updateLoggers();
        } else if (isQuiet()) {
            loggerConfig.setLevel(Level.OFF);
            ctx.updateLoggers();
        } else if (getLogLevel() != null) {
            loggerConfig.setLevel(getLogLevel());
            ctx.updateLoggers();
        }
        // TODO this should probably not be here?
        // ECC does not work properly in the NSS provider
        Security.removeProvider("SunPKCS11-NSS");
        Security.addProvider(new BouncyCastleProvider());
        LOGGER.debug("Using the following security providers");
        for (Provider p : Security.getProviders()) {
            LOGGER.debug("Provider {}, version, {}", p.getName(), p.getVersion());
        }

        // remove stupid Oracle JDK security restriction (otherwise, it is not
        // possible to use strong crypto with Oracle JDK)
        UnlimitedStrengthEnabler.enable();
    }
}
