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
import de.rub.nds.tlsattacker.core.config.converters.FilterConverter;
import de.rub.nds.tlsattacker.core.workflow.filter.FilterType;
import java.util.List;

public class FilterDelegate extends Delegate {

    // Currently, "Possible Values" suggestion is not automatically generated
    // for List<Enum>.
    // Known issue: https://github.com/cbeust/jcommander/issues/402
    @Parameter(names = "-output_filter", description = "Apply given filters to the workflow trace "
            + "before writing to ouput file. Supply as comma separated list. Try also: -list filters.", converter = FilterConverter.class)
    private List<FilterType> filters = null;

    public FilterDelegate() {
    }

    public List<FilterType> getFilters() {
        if (filters == null) {
            return null;
        }
        return filters;
    }

    public void setFilters(List<FilterType> filters) {
        this.filters = filters;
    }

    @Override
    public void applyDelegate(Config config) {
        if (filters != null) {
            config.setOutputFilters(filters);
        }
    }

}
