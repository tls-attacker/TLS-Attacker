/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.filter;

import de.rub.nds.tlsattacker.core.config.Config;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class FilterFactory {

    private static final Logger LOGGER = LogManager.getLogger();

    public static Filter createWorkflowTraceFilter(FilterType type, Config config) {
        switch (type) {
            case DEFAULT:
                return new DefaultFilter(config);
            case DISCARD_RECORDS:
                return new DiscardRecordsFilter(config);
            default:
                throw new UnsupportedOperationException(type.name() + " not yet implemented");
        }
    }

    private FilterFactory() {}
}
