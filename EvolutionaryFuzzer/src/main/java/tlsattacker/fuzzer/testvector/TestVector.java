/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.testvector;

import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.tls.workflow.action.executor.ExecutorType;
import java.io.Serializable;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlTransient;
import tlsattacker.fuzzer.certificate.ClientCertificateStructure;
import tlsattacker.fuzzer.certificate.ServerCertificateStructure;
import tlsattacker.fuzzer.modification.Modification;

/**
 * A class which unites the Information needed to run a single fuzzer iteration.
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class TestVector implements Serializable {

    /**
     * The WorkflowTrace that should be executed with the TestVector
     */
    private WorkflowTrace trace = null;

    /**
     * The serverCertificate that should be used
     */
    private ServerCertificateStructure serverKeyCert = null;

    /**
     * The clientCertificate that should be used
     */
    private ClientCertificateStructure clientKeyCert = null;

    /**
     * The TestVector that this TestVector was mutated from, can be null if not
     * needed
     */
    @XmlTransient
    private TestVector parent = null;

    /**
     * The List of modifications that were used to generate this TestVector. Can
     * be null if not needed.
     */
    @XmlTransient
    private List<Modification> modificationList = null;

    /**
     * The Type of ActionExecutor that should be used to execute this TestVector
     */
    private ExecutorType executorType;

    public TestVector(WorkflowTrace trace, ServerCertificateStructure keyCertPair,
            ClientCertificateStructure clientKeyCert, ExecutorType executorType, TestVector parent) {
        this.trace = trace;
        this.serverKeyCert = keyCertPair;
        this.clientKeyCert = clientKeyCert;
        this.parent = parent;
        this.modificationList = new LinkedList<Modification>();
        this.executorType = executorType;
    }

    public TestVector() {
        modificationList = new LinkedList<>();
    }

    public void clearModifications() {
        modificationList = new LinkedList<>();
    }

    public ExecutorType getExecutorType() {
        return executorType;
    }

    public void setExecutorType(ExecutorType executorType) {
        this.executorType = executorType;
    }

    public WorkflowTrace getTrace() {
        return trace;
    }

    public void setServerKeyCert(ServerCertificateStructure serverKeyCert) {
        this.serverKeyCert = serverKeyCert;
    }

    public void setClientKeyCert(ClientCertificateStructure clientKeyCert) {
        this.clientKeyCert = clientKeyCert;
    }

    public ClientCertificateStructure getClientKeyCert() {
        return clientKeyCert;
    }

    public ServerCertificateStructure getServerKeyCert() {
        return serverKeyCert;
    }

    /**
     * Adds a modification to the modification List
     * 
     * @param modification
     *            Modification to add
     */
    public void addModification(Modification modification) {
        if (modification != null) {
            modificationList.add(modification);
        }
    }

    public List<Modification> getModificationList() {
        return Collections.unmodifiableList(modificationList);
    }

    public TestVector getParent() {
        return parent;
    }

    @Override
    public int hashCode() {
        int hash = 5;
        hash = 89 * hash + Objects.hashCode(this.trace);
        hash = 89 * hash + Objects.hashCode(this.serverKeyCert);
        hash = 89 * hash + Objects.hashCode(this.clientKeyCert);
        hash = 89 * hash + Objects.hashCode(this.executorType);
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
        final TestVector other = (TestVector) obj;
        if (!this.trace.equals(other.trace)) {
            return false;
        }
        if (!Objects.equals(this.serverKeyCert, other.serverKeyCert)) {
            return false;
        }
        if (!Objects.equals(this.clientKeyCert, other.clientKeyCert)) {
            return false;
        }
        if (this.executorType != other.executorType) {
            return false;
        }
        return true;
    }

    @Override
    public String toString() {
        return "TestVector{" + "trace=" + trace + ", serverKeyCert=" + serverKeyCert + ", clientKeyCert="
                + clientKeyCert + ", parent=" + parent + ", modificationList=" + modificationList + ", executorType="
                + executorType + '}';
    }

}
