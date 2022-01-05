/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.config.delegate;

import com.beust.jcommander.Parameter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.MaxFragmentLength;

public class MaxFragmentLengthDelegate extends Delegate {

    // TODO Add validator, and extend unit test
    @Parameter(names = "-max_fragment_length",
        description = "Maximum fragment length definition for the max fragment length TLS extension (possible byte values 1,2,3, or 4)")
    private Integer maxFragmentLength = null;

    public MaxFragmentLengthDelegate() {
    }

    public Integer getMaxFragmentLength() {
        return maxFragmentLength;
    }

    public void setMaxFragmentLength(Integer maxFragmentLength) {
        this.maxFragmentLength = maxFragmentLength;
    }

    @Override
    public void applyDelegate(Config config) {
        if (maxFragmentLength == null) {
            return;
        }

        config.setAddMaxFragmentLengthExtension(true);
        config.setDefaultMaxFragmentLength(MaxFragmentLength.getMaxFragmentLength(maxFragmentLength.byteValue()));

        // record_size_limit and max_fragment_length are not meant to be used simultaneously
        if (config.isAddRecordSizeLimitExtension()) {
            LOGGER
                .warn("Configured to send record_size_limit and max_fragment_length simultaneously, resuming anyways");
        }
    }
}
