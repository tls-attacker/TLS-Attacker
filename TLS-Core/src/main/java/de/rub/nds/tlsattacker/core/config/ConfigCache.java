/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.config;

import org.apache.commons.lang3.SerializationUtils;

public class ConfigCache {

    private final Config cachedConfig;

    public ConfigCache(Config cachedConfig) {
        this.cachedConfig = cachedConfig;
    }

    public Config getCachedCopy() {
        return SerializationUtils.clone(cachedConfig);
    }

}
