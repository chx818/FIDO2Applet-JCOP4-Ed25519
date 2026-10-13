package us.q3q.fido2;
// TEST ONLY. Exercises adapter logic inside a real Java Card simulator applet context.
import javacard.framework.*;
import org.suut.javacard.pki.curve25519.*;
public final class AdapterProbe extends Applet {
 private final Ed25519Credentials ed=new Ed25519Credentials();
 private final byte[] signing=JCSystem.makeTransientByteArray((short)128,JCSystem.CLEAR_ON_DESELECT);
 private final byte[] scratch=JCSystem.makeTransientByteArray((short)160,JCSystem.CLEAR_ON_DESELECT);
 public static void install(byte[] b,short o,byte l){new AdapterProbe().register();}
 public void process(APDU apdu){
  if(selectingApplet())return;
  try {
   ed.generate(scratch,(short)0,signing,(short)0);
   JCSystem.beginTransaction();boolean rejected=false;
   try{ed.sign(scratch,(short)0,(short)32,scratch,(short)32,signing,(short)0);}
   catch(TransactionException e){rejected=e.getReason()==TransactionException.IN_PROGRESS;}
   if(!rejected||JCSystem.getTransactionDepth()!=1)ISOException.throwIt((short)0x6F01);
   JCSystem.abortTransaction();
   // Preserve original public key and sign with overlapping input/output.
   Util.arrayCopyNonAtomic(scratch,(short)0,scratch,(short)96,(short)32);
   if(ed.sign(scratch,(short)0,(short)32,scratch,(short)0,signing,(short)0)!=64)ISOException.throwIt((short)0x6F02);
   Curve25519PublicKey publicKey=(Curve25519PublicKey)Curve25519KeyBuilder.buildKey(
       Curve25519KeyBuilder.ALG_TYPE_EDDSA_PUBLIC,JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT);
   publicKey.setW(scratch,(short)96,(short)32);
   if(!new Curve25519Signature().verify(publicKey,scratch,(short)96,(short)32,scratch,(short)0,(short)64))
       ISOException.throwIt((short)0x6F03);
   ed.clear();if(ed.isLoaded())ISOException.throwIt((short)0x6F04);
  }finally{if(JCSystem.getTransactionDepth()!=0)JCSystem.abortTransaction();ed.clear();}
 }
}
