/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.config.delegate;

import com.beust.jcommander.Parameter;
import de.rub.nds.protocol.exception.ConfigurationException;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ListDelegateType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsattacker.core.workflow.filter.FilterType;
import java.util.EnumSet;
import org.apache.commons.lang3.StringUtils;

/** Plot a list of supported parameters. */
public class ListDelegate extends Delegate {

    // Setting help=true allows us to surpass any parameters marked as required.
    @Parameter(names = "-list", description = "Plot a list of available parameters")
    private ListDelegateType listDelegateType = null;

    public ListDelegate() {}

    public boolean isSet() {
        return listDelegateType != null;
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
                list = StringUtils.join(CipherSuite.getImplemented(), '\n');
                break;
            case filters:
                list = StringUtils.join(EnumSet.allOf(FilterType.class), '\n');
                break;
            case groups:
                list = StringUtils.join(EnumSet.allOf(NamedGroup.class), '\n');
                break;
            case sign_hash_algos:
                list = StringUtils.join(SignatureAndHashAlgorithm.values(), '\n');
                break;
            case workflow_trace_types:
                list = StringUtils.join(EnumSet.allOf(WorkflowTraceType.class), '\n');
                break;
            default:
                throw new ConfigurationException("Nothing to plot");
        }
        return list;
    }

    @Override
    public void applyDelegate(Config config) {}
}
