/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.config;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParameterException;
import de.rub.nds.tlsattacker.core.config.delegate.Delegate;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import java.io.File;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class TLSDelegateConfig {

    private static final Logger LOGGER = LogManager.getLogger();

    private final List<Delegate> delegateList;
    private final GeneralDelegate generalDelegate;

    @Parameter(names = "-config", description = "This parameter allows you to specify a default TlsConfig")
    private String defaultConfig = null;

    public TLSDelegateConfig(GeneralDelegate delegate) {
        delegateList = new LinkedList<>();
        this.generalDelegate = delegate;
        if (delegate != null) {
            delegateList.add(generalDelegate);
        }
    }

    public final void addDelegate(Delegate delegate) {
        delegateList.add(delegate);
    }

    public Delegate getDelegate(Class<? extends Delegate> delegateClass) {
        for (Delegate delegate : getDelegateList()) {
            if (delegate.getClass().equals(delegateClass)) {
                return delegate;
            }
        }
        return null;
    }

    public List<Delegate> getDelegateList() {
        return Collections.unmodifiableList(delegateList);
    }

    public GeneralDelegate getGeneralDelegate() {
        return generalDelegate;
    }

    public Config createConfig(Config baseConfig) {
        for (Delegate delegate : getDelegateList()) {
            delegate.applyDelegate(baseConfig);
        }
        return baseConfig;
    }

    public final boolean hasDifferentConfig() {
        return defaultConfig != null;
    }

    public Config createConfig() {
        Config config = null;
        if (defaultConfig != null) {
            File configFile = new File(defaultConfig);
            if (configFile.exists()) {
                config = Config.createConfig(configFile);
            } else {
                throw new ParameterException("Could not find config file: " + defaultConfig);
            }
        } else {
            config = Config.createConfig();
        }

        return createConfig(config);
    }
}
