package us.q3q.fido2;

import javacard.framework.JCSystem;
import javacard.framework.TransactionException;
import javacard.framework.Util;
import javacard.security.CryptoException;
import org.suut.javacard.pki.curve25519.Curve25519KeyBuilder;
import org.suut.javacard.pki.curve25519.Curve25519PrivateKey;
import org.suut.javacard.pki.curve25519.Curve25519PublicKey;
import org.suut.javacard.pki.curve25519.Curve25519Signature;

/** JCOP-specific PureEd25519 adapter. No COR arrays or persistent private keys.
 * Public key storage may be persistent; only non-secret public material is written there. */
final class Ed25519Credentials {
    private final Curve25519PrivateKey privateKey;
    private final Curve25519PublicKey publicKey;
    private final Curve25519Signature signature;
    private final byte[] active;

    Ed25519Credentials() {
        privateKey = (Curve25519PrivateKey) Curve25519KeyBuilder.buildKey(
                Curve25519KeyBuilder.ALG_TYPE_EDDSA_PRIVATE, JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT);
        publicKey = (Curve25519PublicKey) Curve25519KeyBuilder.buildKey(
                Curve25519KeyBuilder.ALG_TYPE_EDDSA_PUBLIC, JCSystem.MEMORY_TYPE_PERSISTENT);
        signature = new Curve25519Signature();
        active = JCSystem.makeTransientByteArray((short) 1, JCSystem.CLEAR_ON_DESELECT);
    }

    private void requireNoTransaction() {
        // The binary wrapper starts a transaction and may abort an existing caller transaction.
        if (JCSystem.getTransactionDepth() != 0) {
            TransactionException.throwIt(TransactionException.IN_PROGRESS);
        }
    }

    void generate(byte[] out, short off, byte[] scratchSignature, short scratchOff) {
        requireNoTransaction();
        clear();
        active[0] = 1;
        boolean ok = false;
        try {
            Curve25519KeyBuilder.genKeyPair(privateKey, publicKey);
            if (!privateKey.isInitialized() || !publicKey.isInitialized()
                    || publicKey.getW(out, off) != 32) {
                CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
            }
            // Pairwise consistency check, also for credentials using a separate attestation key.
            if (signature.sign(privateKey, out, off, (short) 32, scratchSignature, scratchOff) != 64
                    || !signature.verify(publicKey, out, off, (short) 32,
                            scratchSignature, scratchOff, (short) 64)) {
                CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
            }
            ok = true;
        } finally {
            Util.arrayFillNonAtomic(scratchSignature, scratchOff, (short) 64, (byte) 0);
            if (!ok) {
                clear();
                Util.arrayFillNonAtomic(out, off, (short) 32, (byte) 0);
            }
        }
    }

    void loadSeed(byte[] seed, short off) {
        clear();
        active[0] = 1;
        // Public storage survives reset; never verify a restored nonresident key
        // against a stale public key from a power-interrupted previous command.
        publicKey.clearKey();
        privateKey.setS(seed, off, (short) 32);
    }

    void loadPublicKey(byte[] encodedPublic, short off) {
        publicKey.setW(encodedPublic, off, (short) 32);
    }

    void exportSeed(byte[] out, short off) {
        if (privateKey.getS(out, off) != 32) {
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }
    }

    boolean isLoaded() {
        return active[0] != 0;
    }

    short sign(byte[] message, short off, short len, byte[] out, short outOff,
               byte[] scratchSignature, short scratchOff) {
        requireNoTransaction();
        boolean ok = false;
        try {
            // PureEdDSA over authData || clientDataHash; never Ed25519ph or SHA256(message).
            // Staging makes overlapping input/output safe without relying on the binary wrapper.
            if (signature.sign(privateKey, message, off, len, scratchSignature, scratchOff) != 64) {
                CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
            }
            if (publicKey.isInitialized()) {
                if (!signature.verify(publicKey, message, off, len,
                        scratchSignature, scratchOff, (short) 64)) {
                    CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
                }
            } else {
                // Nonresident IDs retain the legacy size and contain only the seed.
                // Repeat deterministic PureEd25519 before releasing either signature.
                // This detects inconsistent transient faults, not common-mode faults.
                if (signature.sign(privateKey, message, off, len, scratchSignature, (short)(scratchOff + 64)) != 64) {
                    CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
                }
                byte difference = 0;
                for (short i = 0; i < 64; i++) {
                    difference |= (byte)(scratchSignature[(short)(scratchOff + i)] ^ scratchSignature[(short)(scratchOff + i + 64)]);
                }
                if (difference != 0) {
                    CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
                }
            }
            Util.arrayCopyNonAtomic(scratchSignature, scratchOff, out, outOff, (short) 64);
            ok = true;
            return 64;
        } finally {
            Util.arrayFillNonAtomic(scratchSignature, scratchOff, (short) 128, (byte) 0);
            if (!ok) {
                clear();
                Util.arrayFillNonAtomic(out, outOff, (short) 64, (byte) 0);
            }
        }
    }

    void clear() {
        // ES256-only commands never enter the native Ed25519 backend.
        if (active[0] == 0) {
            return;
        }
        try {
            privateKey.clearKey();
        } finally {
            try {
                publicKey.clearKey();
            } finally {
                active[0] = 0;
            }
        }
    }
}
