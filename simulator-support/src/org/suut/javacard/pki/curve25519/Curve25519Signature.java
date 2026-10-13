package org.suut.javacard.pki.curve25519;
// TEST ONLY: not the native implementation and not a timing/resource model of JCOP.
import javacard.security.*;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.bouncycastle.crypto.params.*;
public final class Curve25519Signature {
 public static int failMode=0;
 public static int calls=0;
 public short sign(PrivateKey key,byte[] m,short o,short l,byte[] out,short oo) {
  calls++;
  if(failMode==1 || (failMode==4 && l>32)) CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
  byte[] seed=new byte[32]; ((Curve25519PrivateKey)key).getS(seed,(short)0);
  Ed25519Signer s=new Ed25519Signer();s.init(true,new Ed25519PrivateKeyParameters(seed,0));
  java.util.Arrays.fill(seed,(byte)0);s.update(m,o,l);byte[] sig=s.generateSignature();
  if(failMode==3 || (failMode==6 && calls%2==0))sig[0]^=1;
  System.arraycopy(sig,0,out,oo,64);return (short)(failMode==2?32:64);
 }
 public boolean verify(PublicKey key,byte[] m,short o,short l,byte[] sig,short so,short sl) {
  byte[] pub=new byte[32];((Curve25519PublicKey)key).getW(pub,(short)0);
  Ed25519Signer s=new Ed25519Signer();s.init(false,new Ed25519PublicKeyParameters(pub,0));s.update(m,o,l);
  return s.verifySignature(java.util.Arrays.copyOfRange(sig,so,so+sl));
 }
}
