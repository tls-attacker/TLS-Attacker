/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.util.Objects;

public class ChangeContextValueAction<T> extends ConnectionBoundAction {

    private static final Logger LOGGER = LogManager.getLogger();

    private T newValue;
    private T oldValue = null;
    private String fieldName;

    public ChangeContextValueAction(String fieldName, T newValue) {
        super();
        this.newValue = newValue;
        this.fieldName = fieldName;
    }

    public ChangeContextValueAction() {
    }

    public void setNewValue(T newValue) {
        this.newValue = newValue;
    }

    public T getNewValue() {
        return newValue;
    }

    public T getOldValue() {
        return oldValue;
    }

    @Override
    public void execute(State state) throws WorkflowExecutionException {
        TlsContext tlsContext = state.getTlsContext(getConnectionAlias());

        if (isExecuted()) {
            throw new WorkflowExecutionException("Action already executed!");
        }

        try {
            Field field = tlsContext.getClass().getDeclaredField(this.fieldName);
            field.setAccessible(true);

            oldValue = (T)field.get(tlsContext);

            field.set(tlsContext, this.newValue);

            LOGGER.info(String.format("Changed %s from %s to %s", this.fieldName, oldValue == null ? "null" : oldValue.toString(), newValue.toString()));
            setExecuted(true);
        } catch (Exception e) {
            LOGGER.error(e);
            throw new WorkflowExecutionException("Action could not be executed");
        }
    }

    @Override
    public void reset() {
        oldValue = null;
        setExecuted(null);
    }

    @Override
    public int hashCode() {
        int hash = 5;
        hash = 83 * hash + Objects.hashCode(this.newValue);
        hash = 83 * hash + Objects.hashCode(this.oldValue);
        return hash;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final ChangeContextValueAction<T> other = (ChangeContextValueAction<T>) obj;
        if (!Objects.equals(this.fieldName, other.getFieldName())) {
            return false;
        }

        if (this.getNewValue().getClass().isArray()) {
            // If T is an array (e.g. byte[]), we need to use reflection to check equality
            if (this.newValue != null && other.newValue != null) {
                int length = Array.getLength(this.newValue);
                int length2 = Array.getLength(other.newValue);
                if (length != length2) return false;

                for (int i = 0; i < length; i++) {
                    if (!Array.get(this.newValue, i).equals(Array.get(other.newValue, i))) {
                        return false;
                    }
                }
            }
            if (this.oldValue != null && other.oldValue != null) {
                int length = Array.getLength(this.oldValue);
                int length2 = Array.getLength(other.oldValue);
                if (length != length2) return false;

                for (int i = 0; i < length; i++) {
                    if (!Array.get(this.oldValue, i).equals(Array.get(other.oldValue, i))) {
                        return false;
                    }
                }
            }
            if (this.oldValue == null && other.oldValue != null) return false;
            if (this.newValue == null && other.newValue != null) return false;
            return true;
        }

        if (!Objects.equals(this.oldValue, other.oldValue) ||
            !Objects.equals(this.newValue, other.newValue)) {
            return false;
        }

        return true;
    }

    @Override
    public boolean executedAsPlanned() {
        return isExecuted();
    }

    public String getFieldName() {
        return fieldName;
    }

    public void setFieldName(String fieldName) {
        this.fieldName = fieldName;
    }
}
