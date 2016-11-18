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
import java.util.logging.Logger;
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

    private static final Logger LOG = Logger.getLogger(TestVector.class.getName());
}
