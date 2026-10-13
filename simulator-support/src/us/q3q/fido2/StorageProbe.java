package us.q3q.fido2;
// TEST ONLY: no production entrypoint; verifies that short inputs never require padding bytes from caller.
import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.Cipher;
public final class StorageProbe extends Applet {
 public static void install(byte[] b,short o,byte l){new StorageProbe().register();}
 public void process(APDU apdu){
  if(selectingApplet())return;
  AESKey key=(AESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT,KeyBuilder.LENGTH_AES_256,false);
  key.setKey(new byte[32],(short)0);
  RandomData rng=RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
  Cipher cipher=Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD,false);
  byte[] tiny={(byte)0x5A};byte[] publicKey=new byte[64];byte[] out=new byte[64];
  ResidentKeyData r=new ResidentKeyData(rng,key,cipher,publicKey,(short)0,(short)64,tiny,(short)0,(byte)1,true);
  r.setRpId(key,cipher,tiny,(short)0,(byte)1);
  r.unpackCredBlob(key,cipher,out,(short)0);
  if(out[0]!=tiny[0])ISOException.throwIt((short)0x6F11);
  for(short i=1;i<16;i++)if(out[i]!=0)ISOException.throwIt((short)0x6F12);
  r.unpackRpId(key,cipher,out,(short)0);
  if(out[0]!=tiny[0])ISOException.throwIt((short)0x6F13);
  for(short i=1;i<16;i++)if(out[i]!=0)ISOException.throwIt((short)0x6F14);
  r.setUser(key,cipher,publicKey,(short)0,(byte)32,publicKey,(short)0,(byte)32);
  r.setUser(key,cipher,tiny,(short)0,(byte)1,tiny,(short)0,(byte)1);
  r.unpackUserID(key,cipher,out,(short)0);
  for(short i=1;i<32;i++)if(out[i]!=0)ISOException.throwIt((short)0x6F15);
  r.unpackUserName(key,cipher,out,(short)0);
  for(short i=1;i<32;i++)if(out[i]!=0)ISOException.throwIt((short)0x6F16);
  // Same first plaintext block, same AES key, distinct domains must use distinct IV blocks.
  ResidentKeyData same=new ResidentKeyData(rng,key,cipher,publicKey,(short)0,(short)64,tiny,(short)0,(byte)0,true);
  same.setRpId(key,cipher,publicKey,(short)0,(byte)32);same.emitLargeBlobKey(key,cipher,out,(short)0);
  try {
   java.lang.reflect.Field field=ResidentKeyData.class.getDeclaredField("rpId");field.setAccessible(true);
   byte[] rp=(byte[])field.get(same);
   if(Util.arrayCompare(out,(short)0,rp,(short)0,(short)16)==0)ISOException.throwIt((short)0x6F17);
  }catch(ReflectiveOperationException ex){ISOException.throwIt((short)0x6F18);}
 }
}
