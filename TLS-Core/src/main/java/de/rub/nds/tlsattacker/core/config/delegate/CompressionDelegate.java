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
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import java.util.Collections;
import java.util.List;

public class CompressionDelegate extends Delegate {

    @Parameter(names = "-compression", description = "TLS compression methods to use, divided by a comma. "
        + "(currently, only NULL compression is supported)")
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
