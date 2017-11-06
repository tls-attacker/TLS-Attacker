/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.config.delegate;

import com.beust.jcommander.Parameter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.converters.CompressionMethodConverter;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import java.util.Collections;
import java.util.List;

public class CompressionDelegate extends Delegate {

    @Parameter(names = "-compression", description = "TLS compression methods to use, divided by a comma. "
            + "(currently, only NULL compression is supported)", converter = CompressionMethodConverter.class)
    private List<CompressionMethod> compressionMethods;

    public CompressionDelegate() {
    }

    public List<CompressionMethod> getCompressionMethods() {
        if (compressionMethods == null) {
            return null;
        }
        return Collections.unmodifiableList(compressionMethods);
    }

    public void setCompressionMethods(List<CompressionMethod> compressionMethods) {
        this.compressionMethods = compressionMethods;
    }

    @Override
    public void applyDelegate(Config config) {
        if (compressionMethods != null) {
            config.setDefaultClientSupportedCompressionMethods(compressionMethods);
            config.setDefaultServerSupportedCompressionMethods(compressionMethods);
            if (compressionMethods.size() > 0) {
                config.setDefaultSelectedCompressionMethod(compressionMethods.get(0));
            }
        }
    }

}
