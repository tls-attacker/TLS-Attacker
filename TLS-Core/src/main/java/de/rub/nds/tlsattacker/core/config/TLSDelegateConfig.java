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
import de.rub.nds.tlsattacker.core.config.delegate.Delegate;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.core.workflow.TlsConfig;
import java.io.File;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public abstract class TLSDelegateConfig {

    protected static final Logger LOGGER = LogManager.getLogger("Config");

    private final List<Delegate> delegateList;
    private final GeneralDelegate generalDelegate;

    @Parameter(names = "-config", description = "This parameter allows you to specify a default TlsConfig")
    private String defaultConfig = null;

    public TLSDelegateConfig(GeneralDelegate delegate) {
        delegateList = new LinkedList<>();
        this.generalDelegate = delegate;
        delegateList.add(generalDelegate);
    }

    public void addDelegate(Delegate delegate) {
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

    public TlsConfig createConfig() {
        TlsConfig config = null;
        if (defaultConfig != null) {
            File configFile = new File(defaultConfig);
            if (configFile.exists()) {
                config = TlsConfig.createConfig(configFile);
            } else {
                LOGGER.warn("Could not find default Config File");
                config = TlsConfig.createConfig();
            }
        } else {
            config = TlsConfig.createConfig();
        }
        for (Delegate delegate : getDelegateList()) {
            delegate.applyDelegate(config);
        }
        return config;
    }

}
