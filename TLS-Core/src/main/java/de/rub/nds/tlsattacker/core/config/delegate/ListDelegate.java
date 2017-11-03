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
import de.rub.nds.tlsattacker.core.config.converters.ListDelegateConverter;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ListDelegateType;
import de.rub.nds.tlsattacker.core.constants.NamedCurve;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsattacker.core.workflow.filter.FilterType;
import de.rub.nds.tlsattacker.util.StringHelper;

/**
 * Plot a list of supported parameters.
 */
public class ListDelegate extends Delegate {

    // Setting help=true allows us to surpass any parameters marked as required.
    @Parameter(names = "-list", description = "Plot a list of available parameters", help = true, converter = ListDelegateConverter.class)
    private ListDelegateType listDelegateType = null;

    public ListDelegate() {
    }

    public boolean isSet() {
        return (listDelegateType != null);
    }

    public void plotListing() {
        System.out.println(getListing());
    }

    public String getListing() {
        if (listDelegateType == null) {
            throw new ConfigurationException("Nothing to plot");
        }

        String list = null;
        switch (listDelegateType) {
            case ciphers:
                list = StringHelper.join(CipherSuite.getImplemented());
                break;
            case filters:
                list = StringHelper.enumToString(FilterType.class);
                break;
            case curves:
                list = StringHelper.enumToString(NamedCurve.class);
                break;
            case sign_hash_algos:
                list = StringHelper.join(SignatureAndHashAlgorithm.values());
                break;
            case workflow_trace_types:
                list = StringHelper.enumToString(WorkflowTraceType.class);
        }
        return list;
    }

    @Override
    public void applyDelegate(Config config) {
    }
}
