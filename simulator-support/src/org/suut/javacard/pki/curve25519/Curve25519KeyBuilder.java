package org.suut.javacard.pki.curve25519;
// TEST ONLY: reference Ed25519 backend, never included in the CAP.
import javacard.framework.*;
import javacard.security.*;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;

public final class Curve25519KeyBuilder {
 public static final byte ALG_TYPE_EDDSA_PRIVATE=(byte)0x81, ALG_TYPE_EDDSA_PUBLIC=(byte)0x80;
 public static int allocations=0;
 public static Key buildKey(byte type,byte memory) {
  if(memory!=JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT && !(type==ALG_TYPE_EDDSA_PUBLIC && memory==JCSystem.MEMORY_TYPE_PERSISTENT)) throw new AssertionError("Private seed must be COD");
  allocations++;
  if(type==ALG_TYPE_EDDSA_PRIVATE)return new Priv();
  if(type==ALG_TYPE_EDDSA_PUBLIC)return new Pub(memory);
  throw new IllegalArgumentException();
 }
 public static void genKeyPair(PrivateKey pr,PublicKey pu) {
  byte[] seed=new byte[32]; new java.security.SecureRandom().nextBytes(seed);
  ((Priv)pr).setS(seed,(short)0,(short)32);
  byte[] pub=new Ed25519PrivateKeyParameters(seed,0).generatePublicKey().getEncoded();
  ((Pub)pu).setW(pub,(short)0,(short)32);java.util.Arrays.fill(seed,(byte)0);
 }
 static abstract class Base implements Key,Curve25519Key {
  final byte[] bytes;
  final byte memory;
  final byte[] state;
  Base(){this(JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT);}
  Base(byte memory){this.memory=memory;bytes=memory==JCSystem.MEMORY_TYPE_PERSISTENT?new byte[32]:JCSystem.makeTransientByteArray((short)32,JCSystem.CLEAR_ON_DESELECT);state=memory==JCSystem.MEMORY_TYPE_PERSISTENT?new byte[1]:JCSystem.makeTransientByteArray((short)1,JCSystem.CLEAR_ON_DESELECT);}
  public void clearKey(){if(Curve25519Signature.failMode==5 && this instanceof Priv && isInitialized())CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);Util.arrayFillNonAtomic(bytes,(short)0,(short)32,(byte)0);state[0]=0;}
  public short getSize(){return 256;}
  public byte getKeyMemoryType(){return memory;}
  public boolean isInitialized(){return state[0]!=0;}
  short get(byte[] b,short o){if(!isInitialized())CryptoException.throwIt(CryptoException.UNINITIALIZED_KEY);Util.arrayCopyNonAtomic(bytes,(short)0,b,o,(short)32);return 32;}
  void set(byte[] b,short o,short l){if(l!=32)CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);Util.arrayCopyNonAtomic(b,o,bytes,(short)0,l);state[0]=1;}
 }
 static final class Priv extends Base implements Curve25519PrivateKey {
  public byte getType(){return ALG_TYPE_EDDSA_PRIVATE;}
  public short getS(byte[] b,short o){return get(b,o);}
  public void setS(byte[] b,short o,short l){set(b,o,l);}
 }
 static final class Pub extends Base implements Curve25519PublicKey {
  Pub(byte memory){super(memory);}
  public byte getType(){return ALG_TYPE_EDDSA_PUBLIC;}
  public short getW(byte[] b,short o){return get(b,o);}
  public void setW(byte[] b,short o,short l){set(b,o,l);}
 }
}
