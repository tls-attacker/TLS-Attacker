/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.config.delegate;

import com.beust.jcommander.Parameter;
import de.rub.nds.tlsattacker.tls.config.converters.CipherSuiteConverter;
import de.rub.nds.tlsattacker.tls.config.delegate.Delegate;
import de.rub.nds.tlsattacker.tls.constants.CipherSuite;
import de.rub.nds.tlsattacker.tls.workflow.TlsConfig;
import java.util.LinkedList;
import java.util.List;
import tlsattacker.fuzzer.mutator.certificate.FixedCertificateMutator;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class CertMutatorModuleDelegate extends Delegate {

    /**
     * The certificate mutator that should be used
     */
    @Parameter(names = "-certificate_mutator", description = "The Mutator the Fuzzer uses to generate new Certificates. Possible: "
            + FixedCertificateMutator.optionName)
    private String certMutator = "fixed";

    public CertMutatorModuleDelegate() {
    }

    @Override
    public void applyDelegate(TlsConfig config) {
    }

}
