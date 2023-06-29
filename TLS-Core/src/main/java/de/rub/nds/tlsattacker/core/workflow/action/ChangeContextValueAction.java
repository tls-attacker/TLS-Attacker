/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.state.State;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlElementWrapper;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.XmlSeeAlso;
import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * This action allows to change a value of the {@link TlsContext}. The field that should be changed
 * is referenced by a string.
 *
 * <p>WARNING: This might not work for every field inside the context, especially when the
 * WorkflowTrace is copied. There might be serialization/deserialization issues with the types used
 * in the {@link TlsContext}.
 *
 * @param <T> Object type of the field inside the {@link TlsContext}
 */
@XmlSeeAlso(TlsContext.class)
@XmlRootElement
public class ChangeContextValueAction<T> extends ConnectionBoundAction {

    private static final Logger LOGGER = LogManager.getLogger();

    private T newValue;

    @XmlElementWrapper(name = "newValueList")
    @XmlElement(name = "newValue")
    private List<T> newValueList;

    private T oldValue;
    private List<T> oldValueList;

    private String fieldName;

    @XmlElement private Boolean usesList = null;

    public ChangeContextValueAction(String fieldName, T newValue) {
        super();
        this.newValue = newValue;
        this.fieldName = fieldName;
    }

    public ChangeContextValueAction(String fieldName, List<T> newValueList) {
        super();
        this.usesList = true;
        this.newValueList = newValueList;
        this.fieldName = fieldName;
    }

    public ChangeContextValueAction(String fieldName, T... newValueList) {
        this(fieldName, Arrays.asList(newValueList));
    }

    public ChangeContextValueAction() {}

    @Override
    public void execute(State state) throws ActionExecutionException {
        TlsContext tlsContext = state.getContext(getConnectionAlias()).getTlsContext();

        if (isExecuted()) {
            throw new ActionExecutionException("Action already executed!");
        }

        try {
            Field field = tlsContext.getClass().getDeclaredField(this.fieldName);
            field.setAccessible(true);

            if (!isUsesList()) {
                oldValue = (T) field.get(tlsContext);
                field.set(tlsContext, this.newValue);
                LOGGER.info(
                        String.format(
                                "Changed %s from %s to %s",
                                this.fieldName,
                                oldValue == null ? "null" : oldValue.toString(),
                                newValue.toString()));
            } else {
                oldValueList = (List<T>) field.get(tlsContext);
                field.set(tlsContext, this.newValueList);
                LOGGER.info(
                        String.format(
                                "Changed %s from %s to %s",
                                this.fieldName,
                                oldValueList == null ? "null" : oldValueList.toString(),
                                newValueList.toString()));
            }

            setExecuted(true);
        } catch (Exception e) {
            LOGGER.error(e);
            throw new ActionExecutionException("Action could not be executed");
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

        if (!isUsesList()
                && this.getNewValue() != null
                && this.getNewValue().getClass().isArray()) {
            // If T is an array (e.g. byte[]), we need to use reflection to
            // check equality
            if (this.newValue != null && other.newValue != null) {
                int length = Array.getLength(this.newValue);
                int length2 = Array.getLength(other.newValue);
                if (length != length2) {
                    return false;
                }

                for (int i = 0; i < length; i++) {
                    if (!Array.get(this.newValue, i).equals(Array.get(other.newValue, i))) {
                        return false;
                    }
                }
            }
            if (this.oldValue != null && other.oldValue != null) {
                int length = Array.getLength(this.oldValue);
                int length2 = Array.getLength(other.oldValue);
                if (length != length2) {
                    return false;
                }

                for (int i = 0; i < length; i++) {
                    if (!Array.get(this.oldValue, i).equals(Array.get(other.oldValue, i))) {
                        return false;
                    }
                }
            }
            if (this.oldValue == null && other.oldValue != null) {
                return false;
            }
            if (this.newValue == null && other.newValue != null) {
                return false;
            }
            return true;
        }

        if (!isUsesList()) {
            return Objects.equals(this.oldValue, other.oldValue)
                    && Objects.equals(this.newValue, other.newValue);
        } else {
            return this.newValueList.equals(other.newValueList)
                    && (this.oldValueList == other.oldValueList
                            || this.oldValueList.equals(other.oldValueList));
        }
    }

    @Override
    public boolean executedAsPlanned() {
        return isExecuted();
    }

    private boolean isUsesList() {
        if (usesList != null) {
            return usesList;
        }
        return false;
    }

    public void setNewValue(T newValue) {
        if (isUsesList()) {
            throw new UnsupportedOperationException("The action was initialized with a list");
        }
        this.newValue = newValue;
    }

    public void setNewValue(List<T> newValue) {
        if (!isUsesList()) {
            throw new UnsupportedOperationException("The action was not initialized with a list");
        }
        this.newValueList = newValue;
    }

    public void setNewValue(T... newValue) {
        this.setNewValue(Arrays.asList(newValue));
    }

    public T getNewValue() {
        if (isUsesList()) {
            throw new UnsupportedOperationException("The action was initialized with a list");
        }
        return newValue;
    }

    public List<T> getNewValueList() {
        if (!isUsesList()) {
            throw new UnsupportedOperationException("The action was not initialized with a list");
        }
        return newValueList;
    }

    public T getOldValue() {
        if (isUsesList()) {
            throw new UnsupportedOperationException("The action was initialized with a list");
        }
        return oldValue;
    }

    public List<T> getOldValueList() {
        if (!isUsesList()) {
            throw new UnsupportedOperationException("The action was not initialized with a list");
        }
        return oldValueList;
    }

    public String getFieldName() {
        return fieldName;
    }

    public void setFieldName(String fieldName) {
        this.fieldName = fieldName;
    }
}
