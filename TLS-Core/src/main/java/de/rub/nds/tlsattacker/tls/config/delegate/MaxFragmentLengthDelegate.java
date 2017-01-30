/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.config.delegate;

import com.beust.jcommander.Parameter;
import de.rub.nds.tlsattacker.tls.constants.MaxFragmentLength;
import de.rub.nds.tlsattacker.tls.workflow.TlsConfig;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class MaxFragmentLengthDelegate extends Delegate {

    @Parameter(names = "-max_fragment_length", description = "Maximum fragment length definition for the max fragment length TLS extension (possible byte values 1,2,3, or 4)")
    private int maxFragmentLength;

    public MaxFragmentLengthDelegate() {
    }

    public int getMaxFragmentLength() {
        return maxFragmentLength;
    }

    public void setMaxFragmentLength(Integer maxFragmentLength) {
        this.maxFragmentLength = maxFragmentLength;
    }

    @Override
    public void applyDelegate(TlsConfig config) {
        config.setMaxFragmentLength(MaxFragmentLength.getMaxFragmentLength((byte) maxFragmentLength)); // TODO
                                                                                                       // Converter
    }
}
