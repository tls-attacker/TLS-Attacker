/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.config.delegate;

import static de.rub.nds.tlsattacker.core.constants.RecordSizeLimit.MAX_RECORD_SIZE_LIMIT;

import com.beust.jcommander.Parameter;
import de.rub.nds.tlsattacker.core.config.Config;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class RecordSizeLimitDelegate extends Delegate {

    private static final Logger LOGGER = LogManager.getLogger();

    @Parameter(
            names = "-record_size_limit",
            description =
                    "Record size limit to be advertised in the corresponding TLS extension (0 < value < 65536)")
    private Integer recordSizeLimit = null;

    public RecordSizeLimitDelegate() {}

    public Integer getRecordSizeLimit() {
        return recordSizeLimit;
    }

    public void setRecordSizeLimit(Integer recordSizeLimit) {
        this.recordSizeLimit = recordSizeLimit;
    }

    @Override
    public void applyDelegate(Config config) {
        if (recordSizeLimit == null) {
            return;
        }

        // lower bound here is set to zero instead of MIN_RECORD_SIZE_LIMIT to be able to experiment
        if (recordSizeLimit <= 0 || recordSizeLimit > MAX_RECORD_SIZE_LIMIT) {
            LOGGER.debug(
                    "-record_size_limit value ("
                            + recordSizeLimit
                            + ") is out of bounds, ignoring.");
            return;
        }

        config.setAddRecordSizeLimitExtension(true);
        config.setInboundRecordSizeLimit(recordSizeLimit);

        // record_size_limit and max_fragment_length are not meant to be used simultaneously
        if (config.isAddMaxFragmentLengthExtension()) {
            LOGGER.warn(
                    "Configured to send record_size_limit and max_fragment_length simultaneously, resuming anyways");
        }
    }
}
