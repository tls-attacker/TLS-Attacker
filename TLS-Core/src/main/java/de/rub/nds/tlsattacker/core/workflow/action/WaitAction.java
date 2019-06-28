/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.state.State;
import java.util.Objects;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class WaitAction extends TlsAction {

    private static final Logger LOGGER = LogManager.getLogger();

    private Boolean asPlanned;

    /**
     * Default waiting time in milliseconds
     */
    public final static long DEFAULT_WAITING_TIME = 10;

    /**
     * Time to waiting in milliseconds.
     */
    private Long time = new Long(-1);

    public WaitAction(long time) {
        assertValidTime(time);
        this.time = time;
    }

    public WaitAction() {
    }

    @Override
    public void execute(State state) throws WorkflowExecutionException {
        LOGGER.info("Waiting " + time + "ms...");
        try {
            Thread.sleep(time);
            asPlanned = true;
        } catch (InterruptedException ex) {
            LOGGER.error(ex);
            asPlanned = false;
        }
        this.setExecuted(true);
    }

    @Override
    public void reset() {
        this.setExecuted(false);
        asPlanned = null;
    }

    public long getTime() {
        return time;
    }

    public void setTime(long time) {
        assertValidTime(time);
        this.time = time;
    }

    @Override
    public boolean executedAsPlanned() {
        return isExecuted() && Objects.equals(asPlanned, Boolean.TRUE);
    }

    private void assertValidTime(long time) {
        if (time < 0) {
            throw new ConfigurationException("Cannot wait negative time");
        }
    }

    @Override
    public void normalize() {
        if (time == null || time < 0) {
            time = DEFAULT_WAITING_TIME;
        }
        super.normalize();
    }

    /**
     * Add default values from given defaultAction and initialize empty fields.
     */
    @Override
    public void normalize(TlsAction defaultAction) {
        super.normalize(defaultAction);
        if (defaultAction instanceof WaitAction) {
            if (time == null || time < 0) {
                time = ((WaitAction) defaultAction).getTime();
            }
        }
        if (time == null || time < 0) {
            time = DEFAULT_WAITING_TIME;
        }
    }

    /**
     * Filter empty fields and default values.
     */
    @Override
    public void filter() {
        if (time == DEFAULT_WAITING_TIME) {
            time = null;
        }
    }

    /**
     * Filter empty fields and default values given in defaultAction.
     */
    @Override
    public void filter(TlsAction defaultAction) {
        long defaultTime = DEFAULT_WAITING_TIME;
        if (defaultAction instanceof WaitAction) {
            WaitAction a = ((WaitAction) defaultAction);
            if (a.getTime() >= 0) {
                defaultTime = a.getTime();
            }
        }
        if (time == defaultTime) {
            time = null;
        }
    }

    @Override
    public int hashCode() {
        int hash = 3;
        hash = 23 * hash + Objects.hashCode(this.time);
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
        final WaitAction other = (WaitAction) obj;
        return Objects.equals(this.time, other.time);
    }

}
