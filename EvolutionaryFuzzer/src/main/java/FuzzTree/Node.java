/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package FuzzTree;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.logging.Logger;

/**
 * This class represents a BasicTree Class with a Variable amount of Leafs for
 * each Treenode. The data Element should not be null. Every Node has a parent,
 * except the RootNode. Leafs are organized in a List and should only be edited
 * by the Node Class itself.
 * 
 * @author Robert Merget - robert.merget@rub.de
 * @param <T>
 *            Type of Data organized by the Node
 */
public class Node<T> {
    private static final Logger LOG = Logger.getLogger(Node.class.getName());

    private final T data;
    private Node<T> parent = null;
    private final List<Node<T>> children;

    /**
     * 
     * @param data
     *            Data which the Node helds
     */
    public Node(T data) {
	this.data = data;
	children = new ArrayList<>();

    }

    /**
     * Adds a Child to the Node. There are two possibilities to children to the
     * tree. By adding a Node Object or by directly adding the T Object. Parent
     * is automatically set in the Child.
     * 
     * @throws NullPointerException
     *             if null is added as a Child
     * @param child
     *            Node which is added as a Child
     */
    public void addChild(Node<T> child) {
	if (child == null) {
	    throw new NullPointerException("Cannot add null to Tree!");
	}
	children.add(child);
	child.setParent(this);
    }

    /**
     * Adds a Child to the Node. There are two possibilities to children to the
     * tree. By adding a Node Object or by directly adding the T Object. Parent
     * is automatically set in the Child.
     * 
     * @throws NullPointerException
     *             if null is added as a Child
     * @param child
     *            Node which is added as a Child
     */
    public void addChild(T child) {
	if (child == null) {
	    throw new NullPointerException("Cannot add null to Tree!");
	}
	Node<T> c = new Node<>(child);
	children.add(c);
	c.setParent(this);

    }

    /**
     * Returns an unmodifiable List of the Children/Leafs of the Node. Each
     * child may have its own Children which are not directly in this List.
     * 
     * @return Unmodifiable List of Children/Leafs
     */
    public List<Node<T>> getChildren() {
	return Collections.unmodifiableList(children);
    }

    /**
     * Returns the Data Object stored in the Node.
     * 
     * @return Data Element stored in the Node
     */
    public T getData() {
	return data;
    }

    private void setParent(Node<T> parent) {
	if (parent == null) {
	    throw new NullPointerException("Cannot add null as Parent!");
	}
	this.parent = parent;
    }

    /**
     * Returns the Parent Element of the Node. If the Node is the root of the
     * Tree, null is returned.
     * 
     * @return Parent Element of the Node
     */
    public Node<T> getParent() {
	return parent;
    }
}
