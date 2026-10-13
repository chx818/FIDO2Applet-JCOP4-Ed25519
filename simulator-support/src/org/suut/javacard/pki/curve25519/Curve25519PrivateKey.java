package org.suut.javacard.pki.curve25519;

import javacard.security.PrivateKey;
import javacard.security.CryptoException;


/**
 * Interface for private Curve25519 keys
 */
public interface Curve25519PrivateKey extends PrivateKey, Curve25519Key {
    /**
     * Reads the private key into a buffer.
     *
     * @param buffer The buffer in which to write the private key
     * @param offset The offset in buffer at which to start writing
     * @return       The length of data written to buffer (always 32)
     * 
     * @throws java.lang.NullPointerException if buffer is null.
     * @throws javacard.security.CryptoException with reason CryptoException.ILLEGAL_VALUE if the size
     *     of key is not supported (i.e. different than 32).
     */
    public short getS(byte[] buffer, short offset) throws CryptoException;

    /**
     * Sets the private key from a buffer.
     *
     * @param buffer The buffer from which to read the new private key
     * @param offset The offset in buffer from which to start reading
     * @param length The length of the new private key (must be 32)
     * 
     * @throws java.lang.NullPointerException if buffer is null
     * @throws java.lang.ArrayIndexOutOfBoundsException if buffer is smaller than 32 bytes
     * @throws javacard.security.CryptoException with reason CryptoException.UNINITIALIZED_KEY if the
     *     key has not been initialized.
     */
    public void setS(byte[] buffer, short offset, short length) throws CryptoException;
}
