/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.config.converters;

import com.beust.jcommander.IStringConverter;
import com.beust.jcommander.ParameterException;
import de.rub.nds.tlsattacker.core.workflow.action.executor.WorkflowExecutorType;

public class WorkflowExecutorTypeConverter implements IStringConverter<WorkflowExecutorType> {

    @Override
    public WorkflowExecutorType convert(String value) {
        try {
            return WorkflowExecutorType.valueOf(value);
        } catch (IllegalArgumentException e) {
            throw new ParameterException("Could not parse WorkfloweExecutorType.");
        }
    }

}
