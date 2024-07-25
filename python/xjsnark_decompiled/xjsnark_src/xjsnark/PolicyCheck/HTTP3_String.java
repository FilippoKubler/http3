package xjsnark.PolicyCheck;

/*Generated by MPS */

import backend.structure.CircuitGenerator;
import backend.config.Config;
import backend.eval.SampleRun;
import java.io.BufferedReader;
import java.io.FileReader;
import java.math.BigInteger;
import backend.auxTypes.UnsignedInteger;
import util.Util;
import xjsnark.tls13_key_schedules.TLSKeySchedule;
import backend.eval.CircuitEvaluator;

public class HTTP3_String extends CircuitGenerator {



  public static void main(String[] args) {
    Config.multivariateExpressionMinimization = false;
    Config.writeCircuits = true;
    Config.debugVerbose = true;
    Config.outputFilesPath = "files/";
    transcript_path = args[1];
    allowed_url = args[2];
    randomid = args[3];
    pktnum = args[4];
    new HTTP3_String(args);
  }

  public HTTP3_String(String[] s) {
    super("HTTP3_String");
    __generateCircuit();
    if (s[0].equals("pub")) {
      System.out.println("Generate public inputs only");
      this.__generatePublicInputs(new SampleRun(randomid+pktnum, true) {
        public void pre() {
          // **************** Channel Opening Inputs ***************************************** 
          try {
            BufferedReader br = new BufferedReader(new FileReader(transcript_path));
            String HS_line = br.readLine();
            String H2_line = br.readLine();
            String pt2_line = br.readLine();
            String cert_verify_tail_line = br.readLine();
            String server_finished_line = br.readLine();
            String ct3_line = br.readLine();
            String http3_request_line = br.readLine();
            String H_state_tr7_line = br.readLine();
            String tr3_line = br.readLine();
            String cert_verify_tail_head_length_line = br.readLine();
            String http3_request_head_length_line = br.readLine();


            // HS 
            for (int i = 0; i < HS_line.length() / 2; i = i + 1) {
              HS[i].mapValue(new BigInteger(HS_line.substring(2 * i, 2 * i + 2), 16), CircuitGenerator.__getActiveCircuitGenerator().__getCircuitEvaluator());
            }


            // H2 
            for (int i = 0; i < H2_line.length() / 2; i = i + 1) {
              H2[i].mapValue(new BigInteger(H2_line.substring(2 * i, 2 * i + 2), 16), CircuitGenerator.__getActiveCircuitGenerator().__getCircuitEvaluator());
            }


            // TR3 LENGTH 
            TR3_len.mapValue(BigInteger.valueOf(tr3_line.length() / 2), CircuitGenerator.__getActiveCircuitGenerator().__getCircuitEvaluator());


            // CERTIFICATE VERIFY 

            CertVerify_tail_len.mapValue(BigInteger.valueOf(cert_verify_tail_line.length() / 2), CircuitGenerator.__getActiveCircuitGenerator().__getCircuitEvaluator());

            // CERTIFICATE VERIFY TAIL HEAD LENGTH 
            CertVerify_tail_head_len.mapValue(new BigInteger(cert_verify_tail_head_length_line), CircuitGenerator.__getActiveCircuitGenerator().__getCircuitEvaluator());


            // CERTIFICATE VERIFY TAIL + SERVER FINISHED 
            for (int i = 0; i < cert_verify_tail_line.length() / 2; i = i + 1) {
              CertVerifyTail_ServerFinished_ct[i].mapValue(new BigInteger(cert_verify_tail_line.substring(2 * i, 2 * i + 2), 16), CircuitGenerator.__getActiveCircuitGenerator().__getCircuitEvaluator());
            }
            for (int i = 0; i < server_finished_line.length() / 2; i = i + 1) {
              CertVerifyTail_ServerFinished_ct[i + cert_verify_tail_line.length() / 2].mapValue(new BigInteger(server_finished_line.substring(2 * i, 2 * i + 2), 16), CircuitGenerator.__getActiveCircuitGenerator().__getCircuitEvaluator());
            }
            for (int i = (cert_verify_tail_line.length() + server_finished_line.length()) / 2; i < 128; i = i + 1) {
              CertVerifyTail_ServerFinished_ct[i].mapValue(new BigInteger("0"), CircuitGenerator.__getActiveCircuitGenerator().__getCircuitEvaluator());
            }

            // H_STATE_TR7 
            for (int i = 0; i < H_state_tr7_line.length() / 2; i = i + 1) {
              SHA_H_Checkpoint[i].mapValue(new BigInteger(H_state_tr7_line.substring(2 * i, 2 * i + 2), 16), CircuitGenerator.__getActiveCircuitGenerator().__getCircuitEvaluator());
            }


            // REQUEST 
            for (int i = 0; i < http3_request_line.length() / 2; i = i + 1) {
              http3_request_ct[i].mapValue(new BigInteger(http3_request_line.substring(2 * i, 2 * i + 2), 16), CircuitGenerator.__getActiveCircuitGenerator().__getCircuitEvaluator());
            }
            for (int i = http3_request_line.length() / 2; i < MAX_DNS_CT_LEN; i = i + 1) {
              http3_request_ct[i].mapValue(new BigInteger("0"), CircuitGenerator.__getActiveCircuitGenerator().__getCircuitEvaluator());
            }

            http3_request_head_len.mapValue(new BigInteger(http3_request_head_length_line), CircuitGenerator.__getActiveCircuitGenerator().__getCircuitEvaluator());


            // PATH POSITION 


          } catch (Exception ex) {
            System.out.println("Error reading TLS parameters file");
          }

          // ALLOWED URL 
          try {
            // Url string conversion and assignment 
            for (int i = 0; i < allowed_url.length() / 2; i++) {
              url_bytes[i].mapValue(new BigInteger(allowed_url.substring(2 * i, 2 * i + 2), 16), CircuitGenerator.__getActiveCircuitGenerator().__getCircuitEvaluator());
            }
            for (int i = allowed_url.length() / 2; i < MAX_URL_LEN; i++) {
              if (i == allowed_url.length() / 2) {
                url_bytes[i].mapValue(new BigInteger("13"), CircuitGenerator.__getActiveCircuitGenerator().__getCircuitEvaluator());
              } else if (i == (allowed_url.length() / 2) + 1) {
                url_bytes[i].mapValue(new BigInteger("10"), CircuitGenerator.__getActiveCircuitGenerator().__getCircuitEvaluator());
              } else {
                url_bytes[i].mapValue(new BigInteger("0"), CircuitGenerator.__getActiveCircuitGenerator().__getCircuitEvaluator());
              }
            }

            url_length.mapValue(BigInteger.valueOf(allowed_url.length() / 2), CircuitGenerator.__getActiveCircuitGenerator().__getCircuitEvaluator());

            System.out.println("Url assignment done");

          } catch (Exception ex) {
            System.out.println("Error with conversions");
          }
        }
        public void post() {
          System.out.println("Circuit Output: ");

          for (int j = 0; j < values.length; j++) {
            for (int i = 0; i < values[j].length; i++) {
              System.out.print(String.format("%1$02x", values[j][i].getValueFromEvaluator(CircuitGenerator.__getActiveCircuitGenerator().__getCircuitEvaluator())));
            }
            System.out.print("\n");
          }

        }

      });
    } else if (s[0].equals("run")) {
      System.out.println("Normal execution");
      this.__evaluateSampleRun(new SampleRun(randomid+pktnum, true) {
        public void pre() {
          // **************** Channel Opening Inputs ***************************************** 
          try {
            BufferedReader br = new BufferedReader(new FileReader(transcript_path));
            String HS_line = br.readLine();
            String H2_line = br.readLine();
            String pt2_line = br.readLine();
            String cert_verify_tail_line = br.readLine();
            String server_finished_line = br.readLine();
            String ct3_line = br.readLine();
            String http3_request_line = br.readLine();
            String H_state_tr7_line = br.readLine();
            String tr3_line = br.readLine();
            String cert_verify_tail_head_length_line = br.readLine();
            String http3_request_head_length_line = br.readLine();


            // HS 
            for (int i = 0; i < HS_line.length() / 2; i = i + 1) {
              HS[i].mapValue(new BigInteger(HS_line.substring(2 * i, 2 * i + 2), 16), CircuitGenerator.__getActiveCircuitGenerator().__getCircuitEvaluator());
            }


            // H2 
            for (int i = 0; i < H2_line.length() / 2; i = i + 1) {
              H2[i].mapValue(new BigInteger(H2_line.substring(2 * i, 2 * i + 2), 16), CircuitGenerator.__getActiveCircuitGenerator().__getCircuitEvaluator());
            }


            // TR3 LENGTH 
            TR3_len.mapValue(BigInteger.valueOf(tr3_line.length() / 2), CircuitGenerator.__getActiveCircuitGenerator().__getCircuitEvaluator());


            // CERTIFICATE VERIFY 

            CertVerify_tail_len.mapValue(BigInteger.valueOf(cert_verify_tail_line.length() / 2), CircuitGenerator.__getActiveCircuitGenerator().__getCircuitEvaluator());

            // CERTIFICATE VERIFY TAIL HEAD LENGTH 
            CertVerify_tail_head_len.mapValue(new BigInteger(cert_verify_tail_head_length_line), CircuitGenerator.__getActiveCircuitGenerator().__getCircuitEvaluator());


            // CERTIFICATE VERIFY TAIL + SERVER FINISHED 
            for (int i = 0; i < cert_verify_tail_line.length() / 2; i = i + 1) {
              CertVerifyTail_ServerFinished_ct[i].mapValue(new BigInteger(cert_verify_tail_line.substring(2 * i, 2 * i + 2), 16), CircuitGenerator.__getActiveCircuitGenerator().__getCircuitEvaluator());
            }
            for (int i = 0; i < server_finished_line.length() / 2; i = i + 1) {
              CertVerifyTail_ServerFinished_ct[i + cert_verify_tail_line.length() / 2].mapValue(new BigInteger(server_finished_line.substring(2 * i, 2 * i + 2), 16), CircuitGenerator.__getActiveCircuitGenerator().__getCircuitEvaluator());
            }
            for (int i = (cert_verify_tail_line.length() + server_finished_line.length()) / 2; i < 128; i = i + 1) {
              CertVerifyTail_ServerFinished_ct[i].mapValue(new BigInteger("0"), CircuitGenerator.__getActiveCircuitGenerator().__getCircuitEvaluator());
            }

            // H_STATE_TR7 
            for (int i = 0; i < H_state_tr7_line.length() / 2; i = i + 1) {
              SHA_H_Checkpoint[i].mapValue(new BigInteger(H_state_tr7_line.substring(2 * i, 2 * i + 2), 16), CircuitGenerator.__getActiveCircuitGenerator().__getCircuitEvaluator());
            }


            // REQUEST 
            for (int i = 0; i < http3_request_line.length() / 2; i = i + 1) {
              http3_request_ct[i].mapValue(new BigInteger(http3_request_line.substring(2 * i, 2 * i + 2), 16), CircuitGenerator.__getActiveCircuitGenerator().__getCircuitEvaluator());
            }
            for (int i = http3_request_line.length() / 2; i < MAX_DNS_CT_LEN; i = i + 1) {
              http3_request_ct[i].mapValue(new BigInteger("0"), CircuitGenerator.__getActiveCircuitGenerator().__getCircuitEvaluator());
            }

            http3_request_head_len.mapValue(new BigInteger(http3_request_head_length_line), CircuitGenerator.__getActiveCircuitGenerator().__getCircuitEvaluator());


            // PATH POSITION 


          } catch (Exception ex) {
            System.out.println("Error reading TLS parameters file");
          }

          // ALLOWED URL 
          try {
            // Url string conversion and assignment 
            for (int i = 0; i < allowed_url.length() / 2; i++) {
              url_bytes[i].mapValue(new BigInteger(allowed_url.substring(2 * i, 2 * i + 2), 16), CircuitGenerator.__getActiveCircuitGenerator().__getCircuitEvaluator());
            }
            for (int i = allowed_url.length() / 2; i < MAX_URL_LEN; i++) {
              if (i == allowed_url.length() / 2) {
                url_bytes[i].mapValue(new BigInteger("13"), CircuitGenerator.__getActiveCircuitGenerator().__getCircuitEvaluator());
              } else if (i == (allowed_url.length() / 2) + 1) {
                url_bytes[i].mapValue(new BigInteger("10"), CircuitGenerator.__getActiveCircuitGenerator().__getCircuitEvaluator());
              } else {
                url_bytes[i].mapValue(new BigInteger("0"), CircuitGenerator.__getActiveCircuitGenerator().__getCircuitEvaluator());
              }
            }

            url_length.mapValue(BigInteger.valueOf(allowed_url.length() / 2), CircuitGenerator.__getActiveCircuitGenerator().__getCircuitEvaluator());

            System.out.println("Url assignment done");

          } catch (Exception ex) {
            System.out.println("Error with conversions");
          }
        }
        public void post() {
          System.out.println("Circuit Output: ");

          for (int j = 0; j < values.length; j++) {
            for (int i = 0; i < values[j].length; i++) {
              System.out.print(String.format("%1$02x", values[j][i].getValueFromEvaluator(CircuitGenerator.__getActiveCircuitGenerator().__getCircuitEvaluator())));
            }
            System.out.print("\n");
          }

        }

      });
    } else {
      System.out.println("Choose pub to generate public inputs only, run to do the whole execution.");
    }
  }



  public void __init() {
    HS = (UnsignedInteger[]) UnsignedInteger.createZeroArray(CircuitGenerator.__getActiveCircuitGenerator(), new int[]{32}, 8);
    SHA_H_Checkpoint = (UnsignedInteger[]) UnsignedInteger.createZeroArray(CircuitGenerator.__getActiveCircuitGenerator(), new int[]{32}, 8);
    H2 = (UnsignedInteger[]) UnsignedInteger.createZeroArray(CircuitGenerator.__getActiveCircuitGenerator(), new int[]{32}, 8);
    TR3_len = new UnsignedInteger(16, new BigInteger("0"));
    CertVerify_len = new UnsignedInteger(16, new BigInteger("0"));
    CertVerify_tail_len = new UnsignedInteger(8, new BigInteger("0"));
    CertVerify_tail_head_len = new UnsignedInteger(8, new BigInteger("0"));
    CertVerify_ct = (UnsignedInteger[]) UnsignedInteger.createZeroArray(CircuitGenerator.__getActiveCircuitGenerator(), new int[]{264}, 8);
    CertVerifyTail_ServerFinished_ct = (UnsignedInteger[]) UnsignedInteger.createZeroArray(CircuitGenerator.__getActiveCircuitGenerator(), new int[]{128}, 8);
    http3_request_ct = (UnsignedInteger[]) UnsignedInteger.createZeroArray(CircuitGenerator.__getActiveCircuitGenerator(), new int[]{MAX_DNS_CT_LEN}, 8);
    http3_request_head_len = new UnsignedInteger(8, new BigInteger("0"));
    url_bytes = (UnsignedInteger[]) UnsignedInteger.createZeroArray(CircuitGenerator.__getActiveCircuitGenerator(), new int[]{MAX_URL_LEN}, 8);
    url_length = new UnsignedInteger(8, new BigInteger("0"));
    path_position = new UnsignedInteger(8, new BigInteger("0"));
  }

  public UnsignedInteger[] HS;
  public UnsignedInteger[] SHA_H_Checkpoint;
  public UnsignedInteger[] H2;
  public UnsignedInteger TR3_len;
  public UnsignedInteger CertVerify_len;
  public UnsignedInteger CertVerify_tail_len;
  public UnsignedInteger CertVerify_tail_head_len;
  public UnsignedInteger[] CertVerify_ct;
  public UnsignedInteger[] CertVerifyTail_ServerFinished_ct;
  public UnsignedInteger[] http3_request_ct;
  public UnsignedInteger http3_request_head_len;
  public UnsignedInteger[] url_bytes;
  public UnsignedInteger url_length;
  public UnsignedInteger path_position;
  public UnsignedInteger[][] values;
  public UnsignedInteger[] string_http;

  public static String allowed_url;
  public static String transcript_path;
  public static String randomid;
  public static String pktnum;
  public static final int MAX_DNS_CT_LEN = 300;
  public static final int MAX_URL_LEN = 100;
  @Override
  public void __defineInputs() {
    super.__defineInputs();
    TR3_len = UnsignedInteger.createInput(this, 16);
    CertVerify_tail_len = UnsignedInteger.createInput(this, 8);
    url_length = UnsignedInteger.createInput(this, 8);
    CertVerify_tail_head_len = UnsignedInteger.createInput(this, 8);



    H2 = (UnsignedInteger[]) UnsignedInteger.createInputArray(CircuitGenerator.__getActiveCircuitGenerator(), Util.getArrayDimensions(H2), 8);
    CertVerifyTail_ServerFinished_ct = (UnsignedInteger[]) UnsignedInteger.createInputArray(CircuitGenerator.__getActiveCircuitGenerator(), Util.getArrayDimensions(CertVerifyTail_ServerFinished_ct), 8);
    url_bytes = (UnsignedInteger[]) UnsignedInteger.createInputArray(CircuitGenerator.__getActiveCircuitGenerator(), Util.getArrayDimensions(url_bytes), 8);
    http3_request_ct = (UnsignedInteger[]) UnsignedInteger.createInputArray(CircuitGenerator.__getActiveCircuitGenerator(), Util.getArrayDimensions(http3_request_ct), 8);












  }
  @Override
  public void __defineOutputs() {
    super.__defineOutputs();









  }
  @Override
  public void __defineVerifiedWitnesses() {
    super.__defineVerifiedWitnesses();

    http3_request_head_len = UnsignedInteger.createVerifiedWitness(this, 8);



    HS = (UnsignedInteger[]) UnsignedInteger.createVerifiedWitnessArray(CircuitGenerator.__getActiveCircuitGenerator(), Util.getArrayDimensions(HS), 8);
    SHA_H_Checkpoint = (UnsignedInteger[]) UnsignedInteger.createVerifiedWitnessArray(CircuitGenerator.__getActiveCircuitGenerator(), Util.getArrayDimensions(SHA_H_Checkpoint), 8);















  }
  public void outsource() {
    // ********************* Channel Opening ********************** 
    UnsignedInteger[] SHA_H_Checkpoint_32 = xjsnark.util_and_sha.Util.convert_8_to_32(SHA_H_Checkpoint);
    values = TLSKeySchedule.quic_get1RTT_HS_new(HS, H2, TR3_len.copy(16), CertVerifyTail_ServerFinished_ct, CertVerify_tail_len.copy(8), SHA_H_Checkpoint_32, http3_request_ct, CertVerify_tail_head_len.copy(8), http3_request_head_len.copy(8));
    string_http = LabelExtraction.firewall(values[0], url_bytes, url_length.copy(8));
  }
  public int[] str_to_array(String str) {
    int[] asciiVal = new int[str.length()];
    for (int i = 0; i < str.length(); i++) {
      char c = str.charAt(i);
      asciiVal[i] = Character.codePointAt(Character.toString(c), 0);
    }
    return asciiVal;
  }

  public void __generateSampleInput(CircuitEvaluator evaluator) {
    __generateRandomInput(evaluator);
  }

}
