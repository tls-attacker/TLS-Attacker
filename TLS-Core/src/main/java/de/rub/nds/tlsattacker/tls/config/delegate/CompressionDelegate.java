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
import de.rub.nds.tlsattacker.tls.config.converters.CompressionMethodConverter;
import de.rub.nds.tlsattacker.tls.constants.CompressionMethod;
import de.rub.nds.tlsattacker.tls.workflow.TlsConfig;
import java.util.LinkedList;
import java.util.List;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class CompressionDelegate extends Delegate {

    @Parameter(names = "-compression", description = "TLS compression methods to use, divided by a comma. "
            + "(currently, only NULL compression is supported)", converter = CompressionMethodConverter.class)
    private List<CompressionMethod> compressionMethods;

    public CompressionDelegate() {
    }

    public List<CompressionMethod> getCompressionMethods() {
        return compressionMethods;
    }

    public void setCompressionMethods(List<CompressionMethod> compressionMethods) {
        this.compressionMethods = compressionMethods;
    }

    @Override
    public void applyDelegate(TlsConfig config) {
        if (compressionMethods != null) {
            config.setSupportedCompressionMethods(compressionMethods);
        }
    }

}
