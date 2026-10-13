package org.suut.javacard.pki.curve25519;

import javacard.security.PublicKey;
import javacard.security.CryptoException;


/**
 * Interface for public Curve25519 keys
 */
public interface Curve25519PublicKey extends PublicKey, Curve25519Key {
    /**
     * Reads the public key into a buffer.
     *
     * @param buffer The buffer in which to write the public key
     * @param offset The offset in buffer at which to start writing
     * @return       The length of data written to the buffer (always 32)
     * 
     * @throws java.lang.NullPointerException if buffer is null.
     * @throws javacard.security.CryptoException with reason CryptoException.ILLEGAL_VALUE if the size
     *     of key is not supported (i.e. different than 32).
     */
    public short getW(byte[] buffer, short offset) throws CryptoException;

    /**
     * Sets the public key from a buffer.
     *
     * @param buffer The buffer in which to read the new public key
     * @param offset The offset in buffer from which to start reading
     * @param length The length of the new public key (must be 32)
     * 
     * @throws java.lang.NullPointerException if buffer is null
     * @throws java.lang.ArrayIndexOutOfBoundsException if buffer is smaller than 32 bytes
     * @throws javacard.security.CryptoException with reason CryptoException.UNINITIALIZED_KEY if the
     *     key has not been initialized.
     */
    public void setW(byte[] buffer, short offset, short length) throws CryptoException;
}
