package org.suut.javacard.pki.curve25519;


/**
 * Interface common to all types of Curve25519 keys
 */
public interface Curve25519Key {
    /**
     * @return One of the JCSystem.MEMORY_TYPE_* constants
     */
    public byte getKeyMemoryType();
}
