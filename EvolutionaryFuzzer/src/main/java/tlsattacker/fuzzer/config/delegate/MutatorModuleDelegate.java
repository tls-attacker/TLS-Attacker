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
import tlsattacker.fuzzer.mutator.NoneMutator;
import tlsattacker.fuzzer.mutator.SimpleMutator;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class MutatorModuleDelegate extends Delegate {

     /**
     * The mutator that should be used
     */
    @Parameter(names = "-mutator", description = "The Mutator the Fuzzer uses to generate new TestVectors. Possible: "
            + SimpleMutator.optionName + ", " + NoneMutator.optionName + "")
    private String mutator = SimpleMutator.optionName;

    public MutatorModuleDelegate() {
    }

    @Override
    public void applyDelegate(TlsConfig config) {
    }

}
