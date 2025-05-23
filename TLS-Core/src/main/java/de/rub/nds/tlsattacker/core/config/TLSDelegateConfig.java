/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.config;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParameterException;
import com.beust.jcommander.ParametersDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.Delegate;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import java.io.File;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

public abstract class TLSDelegateConfig {

    private final List<Delegate> delegateList;

    @ParametersDelegate private final GeneralDelegate generalDelegate;

    @Parameter(
            names = "-config",
            description = "This parameter allows you to specify a default TlsConfig")
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

    public <T extends Delegate> T getDelegate(Class<T> delegateClass) {
        for (Delegate delegate : getDelegateList()) {
            if (delegate.getClass().equals(delegateClass)) {
                return delegateClass.cast(delegate);
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
            config = new Config();
        }

        return createConfig(config);
    }

    public final boolean hasDifferentConfig() {
        return defaultConfig != null;
    }
}
