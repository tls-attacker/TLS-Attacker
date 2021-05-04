/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.config.delegate;

import com.beust.jcommander.Parameter;
import de.rub.nds.tlsattacker.core.config.Config;
import static de.rub.nds.tlsattacker.core.constants.RecordSizeLimit.MAX_RECORD_SIZE_LIMIT;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class RecordSizeLimitDelegate extends Delegate {

    private static final Logger LOGGER = LogManager.getLogger();

    @Parameter(names = "-record_size_limit",
        description = "Record size limit definition for the TLS extension described in RFC 8449 (0 < value < 65536)")
    private Integer recordSizeLimit = null;

    public RecordSizeLimitDelegate() {
    }

    public Integer getRecordSizeLimit() {
        return recordSizeLimit;
    }

    public void setRecordSizeLimit(Integer recordSizeLimit) {
        this.recordSizeLimit = recordSizeLimit;
    }

    @Override
    public void applyDelegate(Config config) {
        if (recordSizeLimit == null) {
            // "-record_size_limit" not specified
            return;
        }

        // lower bound here is set to zero instead of MIN_RECORD_SIZE_LIMIT to be able to experiment
        // TODO: decide if this is a good idea
        if (recordSizeLimit <= 0 || recordSizeLimit > MAX_RECORD_SIZE_LIMIT) {
            LOGGER.debug("-record_size_limit value (" + recordSizeLimit + ") is out of bounds, ignoring.");
            return;
        }

        config.setAddRecordSizeLimitExtension(true);
        config.setDefaultRecordSizeLimit(recordSizeLimit);
    }
}
