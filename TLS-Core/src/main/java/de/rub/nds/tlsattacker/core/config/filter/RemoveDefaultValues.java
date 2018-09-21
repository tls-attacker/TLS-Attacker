/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.config.filter;

import de.rub.nds.tlsattacker.core.config.Config;
import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class RemoveDefaultValues implements ConfigDisplayFilter {

    private static final Logger LOGGER = LogManager.getLogger();

    @Override
    public void applyFilter(Config config) {
        Config defaultConfig = Config.createConfig();
        for (Field field : Config.class.getDeclaredFields()) {
            if (!(Modifier.isStatic(field.getModifiers()) || Modifier.isFinal(field.getModifiers()))) {
                if (field.getType().isArray() || !field.getType().isPrimitive()) {
                    field.setAccessible(true);
                    try {
                        Object defaultValue = field.get(defaultConfig);
                        Object configValue = field.get(config);
                        if (configValue != null) {
                            if (field.getType().isArray()) {
                                if (Array.getLength(defaultValue) == Array.getLength(configValue)) {
                                    boolean equal = true;
                                    for (int i = 0; i < Array.getLength(defaultValue); i++) {
                                        if (!Array.get(defaultValue, i).equals(Array.get(configValue, i))) {
                                            equal = false;
                                            break;
                                        }
                                    }
                                    if (equal) {
                                        field.set(config, null);
                                    }
                                }
                            } else {
                                if (defaultValue.equals(configValue)) {
                                    field.set(config, null);
                                }
                            }
                        }
                    } catch (IllegalAccessException e) {
                        LOGGER.warn("Could not remove field in Config!", e);
                    }
                    field.setAccessible(false);
                }
            }
        }
    }

}
