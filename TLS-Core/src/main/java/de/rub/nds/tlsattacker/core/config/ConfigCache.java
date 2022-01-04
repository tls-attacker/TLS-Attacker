/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 * <p>
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
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
