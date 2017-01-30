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
import tlsattacker.fuzzer.controller.CommandLineController;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class ControllerModuleDelegate extends Delegate {

    
    /**
     * The controller that should be used
     */
    @Parameter(names = "-controller", description = "The Controller that is used to communicate with the Operator. Possible: "
            + CommandLineController.optionName)
    private String controller = CommandLineController.optionName;


    public ControllerModuleDelegate() {
    }


    @Override
    public void applyDelegate(TlsConfig config) {
    }

}
