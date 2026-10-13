package us.q3q.fido2;
import com.licel.jcardsim.base.Simulator;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.*;
import java.io.*;
import org.suut.javacard.pki.curve25519.*;
public final class SimulatorBridge {
 static final AID AID=AIDUtil.create("A0000006472F0001"), OTHER=AIDUtil.create("F000000001");
 public static final class Other extends Applet {
  public static void install(byte[] b,short o,byte l){new Other().register();}
  public void process(APDU a){}
 }
 static byte[] hex(String s){byte[] b=new byte[s.length()/2];for(int i=0;i<b.length;i++)b[i]=(byte)Integer.parseInt(s.substring(i*2,i*2+2),16);return b;}
 static String hex(byte[] b){StringBuilder s=new StringBuilder();for(byte v:b)s.append(String.format("%02x",v&255));return s.toString();}
 public static void main(String[] args)throws Exception {
  System.setProperty("com.licel.jcardsim.bouncycastle.rsa.allow_unsafe_mod", "true");
  PrintStream protocol=System.out;System.setOut(System.err);
  Simulator sim=new Simulator();BufferedReader input=new BufferedReader(new InputStreamReader(System.in));
  for(String line;(line=input.readLine())!=null;) {
   try {
    if(line.startsWith("INSTALL ")) {
     sim.resetRuntime();sim.reset();byte[] params=hex(line.substring(8));
     sim.installApplet(AID,FIDO2Applet.class,params,(short)0,(byte)params.length);
     sim.installApplet(OTHER,Other.class);sim.selectApplet(AID);protocol.println("OK");
    }else if(line.equals("RESET")){sim.reset();sim.selectApplet(AID);protocol.println("OK");}
    else if(line.equals("DESELECT")){sim.selectApplet(OTHER);sim.selectApplet(AID);protocol.println("OK");}
    else if(line.equals("PROBE")) {
     AID probe=AIDUtil.create("F000000002");
     sim.installApplet(probe,AdapterProbe.class);sim.selectApplet(probe);
     byte[] result=sim.transmitCommand(hex("00000000"));sim.selectApplet(AID);protocol.println(hex(result));
    }
    else if(line.equals("STORAGEPROBE")) {
     AID probe=AIDUtil.create("F000000003");sim.installApplet(probe,StorageProbe.class);sim.selectApplet(probe);
     byte[] result=sim.transmitCommand(hex("00000000"));sim.selectApplet(AID);protocol.println(hex(result));
    }
    else if(line.equals("PERSISTENCEPROBE")) {
     AID probe=AIDUtil.create("F000000004");sim.installApplet(probe,PersistenceProbe.class);sim.selectApplet(probe);
     byte[] first=sim.transmitCommand(hex("00000000"));sim.reset();sim.selectApplet(probe);
     byte[] second=sim.transmitCommand(hex("00010000"));sim.selectApplet(AID);
     protocol.println(hex(first)+hex(second));
    }
    else if(line.startsWith("FAULT ")){Curve25519Signature.failMode=Integer.parseInt(line.substring(6));protocol.println("OK");}
    else if(line.equals("EXIT")){break;}
    else {protocol.println(hex(sim.transmitCommand(hex(line))));}
   }catch(Throwable t){t.printStackTrace(System.err);protocol.println("ERROR "+t);}
   protocol.flush();
  }
 }
}
