package us.q3q.fido2;
// TEST ONLY: simulates power interruption between key generation and normal APDU cleanup.
import javacard.framework.*;
import org.suut.javacard.pki.curve25519.*;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
public final class PersistenceProbe extends Applet {
    private final Ed25519Credentials ed = new Ed25519Credentials();
    private final byte[] oldSeed = new byte[32]; // Test fixture only; never in production CAP.
    private final byte[] work = JCSystem.makeTransientByteArray((short)160, JCSystem.CLEAR_ON_DESELECT);
    private final byte[] io = JCSystem.makeTransientByteArray((short)128, JCSystem.CLEAR_ON_DESELECT);
    public static void install(byte[] b,short o,byte l) { new PersistenceProbe().register(); }
    public void process(APDU apdu) {
        if (selectingApplet()) return;
        if (apdu.getBuffer()[ISO7816.OFFSET_INS] == 0) {
            ed.generate(io, (short)0, work, (short)16);
            ed.exportSeed(oldSeed, (short)0);
            // Intentionally omit cleanup in test fixture; SimulatorBridge resets the card now.
            return;
        }
        try {
            java.lang.reflect.Field f=Ed25519Credentials.class.getDeclaredField("publicKey");
            f.setAccessible(true);
            Curve25519PublicKey publicKey=(Curve25519PublicKey)f.get(ed);
            if (ed.isLoaded() || !publicKey.isInitialized()
                    || publicKey.getKeyMemoryType()!=JCSystem.MEMORY_TYPE_PERSISTENT) {
                ISOException.throwIt((short)0x6F21);
            }
            oldSeed[0] ^= 0x55; // Different restored nonresident credential after reset.
            ed.loadSeed(oldSeed,(short)0);
            if(publicKey.isInitialized()) ISOException.throwIt((short)0x6F22);
            Util.arrayFillNonAtomic(work,(short)0,(short)160,(byte)0x5A);
            Util.arrayFillNonAtomic(io,(short)0,(short)128,(byte)0x36);
            ed.sign(io,(short)0,(short)32,io,(short)32,work,(short)16);
            for(short i=0;i<160;i++) {
                byte expected=(byte)(i>=16 && i<144 ? 0 : 0x5A);
                if(work[i]!=expected) ISOException.throwIt((short)0x6F23);
            }
            Ed25519Signer check=new Ed25519Signer();
            check.init(false,new Ed25519PrivateKeyParameters(oldSeed,0).generatePublicKey());
            check.update(io,0,32);
            if(!check.verifySignature(java.util.Arrays.copyOfRange(io,32,96)))
                ISOException.throwIt((short)0x6F24);
            ed.clear();
            if(ed.isLoaded() || publicKey.isInitialized()) ISOException.throwIt((short)0x6F25);
        } catch (ReflectiveOperationException error) {
            ISOException.throwIt((short)0x6F26);
        } finally {
            ed.clear();
        }
    }
}
