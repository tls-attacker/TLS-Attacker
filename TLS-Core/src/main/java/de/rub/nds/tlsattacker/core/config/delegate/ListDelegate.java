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
import java.util.Arrays;
import java.util.Collection;
import java.util.EnumSet;

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
                list = join(CipherSuite.getImplemented());
                break;
            case filters:
                list = enumToString(FilterType.class);
                break;
            case curves:
                list = enumToString(NamedCurve.class);
                break;
            case sign_hash_algos:
                list = join(SignatureAndHashAlgorithm.values());
                break;
            case workflow_trace_types:
                list = enumToString(WorkflowTraceType.class);
                ;
        }
        return list;
    }

    @Override
    public void applyDelegate(Config config) {
    }

    public <E extends Enum<E>> String enumToString(Class<E> e) {
        return join(EnumSet.allOf(e));
    }

    public String join(Object[] objects) {
        return join(Arrays.asList(objects));
    }

    public String join(Collection collection) {
        StringBuilder sb = new StringBuilder();
        for (Object o : collection) {
            sb.append(o.toString()).append(System.lineSeparator());
        }
        sb.deleteCharAt(sb.lastIndexOf(System.lineSeparator()));
        return sb.toString();
    }
}
