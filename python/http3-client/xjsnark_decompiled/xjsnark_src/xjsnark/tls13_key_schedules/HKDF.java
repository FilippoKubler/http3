package xjsnark.tls13_key_schedules;

/*Generated by MPS */

import backend.auxTypes.UnsignedInteger;
import xjsnark.util_and_sha.Util;
import xjsnark.util_and_sha.SHA2;
import backend.structure.CircuitGenerator;

public class HKDF {

  // This file implements both HMAC and HKDF (RFC 5869) with SHA256 as the base hash function.
  // The three main functions to implement are:
  // (1) HMAC
  // (2) HKDF Extract 
  // (3) HKDF Expand - this is a iterative function, but only one iteration is required in TLS 1.3
  // The last two call HMAC after processing their inputs.
  // Furthermore, TLS 1.3 uses Expand in particular ways depending on what the desired output is (a secret, key or iv)
  // It also pre-processes the inputs in specific ways, such as prepending the string "tls13 " to the label

  // Fixed bytes used in the HMAC function
  public static final int IPAD = 0x36;
  public static final int OPAD = 0x5c;


  // HMAC function:
  // HMAC(key, salt) = H((k \xor ipad) || H((k \xor opad)  ||  salt)) 
  // where ipad and opad are fixed bytes (0x36 and 0x5c respective)
  public static UnsignedInteger[] hmac(UnsignedInteger[] key, UnsignedInteger[] salt) {

    // the key is padded to 512 bits when using SHA256 
    if (key.length < 64) {
      UnsignedInteger[] key_pad = Util.new_zero_array(64 - key.length);
      key = Util.concat(key, key_pad);
    }

    // We xor every byte of the key with ipad and opad to generate the following two strings 
    UnsignedInteger[] key_ipad = Util.xor_with_byte(key, UnsignedInteger.instantiateFrom(8, IPAD).copy(8));
    UnsignedInteger[] key_opad = Util.xor_with_byte(key, UnsignedInteger.instantiateFrom(8, OPAD).copy(8));

    // The inner of the two nested hashes 
    UnsignedInteger[] inner_hash = SHA2.sha2(Util.concat(key_ipad, salt));

    // The outer of the two nested hashes 
    return SHA2.sha2(Util.concat(key_opad, inner_hash));
  }


  //  HKDF Extract
  public static UnsignedInteger[] hkdf_extract(UnsignedInteger[] salt, UnsignedInteger[] key) {
    return hmac(salt, key);
  }

  // One iteration of HKDF expand, the one_byte being appending to the 'info' input
  public static UnsignedInteger[] hkdf_expand(UnsignedInteger[] key, UnsignedInteger[] info) {
    UnsignedInteger[] the_one_byte = {UnsignedInteger.instantiateFrom(8, 1).copy(8)};
    UnsignedInteger[] label = Util.concat(info, the_one_byte);

    return hmac(key, label);
  }


  // This function generates the label to be used by the TLS 1.3 algorithm when calling HKDF
  // The description is in RFC 8446, Section 7.1
  public static UnsignedInteger[] get_tls_hkdf_label(int output_len, String label_string, UnsignedInteger[] context_hash) {

    // Get length of the desired output represented as 2 bytes 
    UnsignedInteger output_len_in_bytes = UnsignedInteger.instantiateFrom(16, output_len).copy(16);
    UnsignedInteger[] output_len_bytes = {UnsignedInteger.instantiateFrom(8, output_len_in_bytes.shiftRight(8)).copy(8), UnsignedInteger.instantiateFrom(8, output_len_in_bytes).copy(8)};

    // Append "tls13 " to the label string  
    UnsignedInteger[] label_bytes = Util.string_to_bytes("tls13 " + label_string);

    // Prepend the length of the new label represented as 1 byte 
    UnsignedInteger[] label_len_byte = {UnsignedInteger.instantiateFrom(8, 6 + label_string.length()).copy(8)};

    // Reprsent the length of the context hash as 1 byte 
    UnsignedInteger[] context_hash_len_byte = {UnsignedInteger.instantiateFrom(8, context_hash.length).copy(8)};

    // The final label is the concatenation of the following: 
    // 1. length of the required output as 2 bytes 
    // 2. the label prepended by its length as one byte 
    // 3. the context hash prepended by its length as one byte 
    UnsignedInteger[][] arrays_to_concat = {output_len_bytes, label_len_byte, label_bytes, context_hash_len_byte, context_hash};
    UnsignedInteger[] hkdf_label = Util.concat(arrays_to_concat);

    return hkdf_label;
  }

  // The three functions below call HKDF Expand
  // when the output generated is a key and a iv and a TLS secret, respectively.
  // Descriptions are in RFC 8446, Section 7.3

  public static UnsignedInteger[] hkdf_expand_derive_tk(UnsignedInteger[] secret, int key_length) {
    // For AES GCM 128, the key length is 16 
    UnsignedInteger[] hkdf_label = get_tls_hkdf_label(key_length, "key", (UnsignedInteger[]) UnsignedInteger.createZeroArray(CircuitGenerator.__getActiveCircuitGenerator(), new int[]{0}, 8));
    return Util.get_prefix(hkdf_expand(secret, hkdf_label), key_length);
  }

  public static UnsignedInteger[] hkdf_expand_derive_iv(UnsignedInteger[] secret, int iv_length) {
    // For AES GCM 128, the iv length is 12 
    UnsignedInteger[] hkdf_label = get_tls_hkdf_label(iv_length, "iv", (UnsignedInteger[]) UnsignedInteger.createZeroArray(CircuitGenerator.__getActiveCircuitGenerator(), new int[]{0}, 8));
    return Util.get_prefix(hkdf_expand(secret, hkdf_label), iv_length);
  }

  public static UnsignedInteger[] hkdf_expand_derive_secret(UnsignedInteger[] secret, String label_string, UnsignedInteger[] context_hash) {
    // The length of all TLS 1.3 secrets are 32 bytes 

    UnsignedInteger[] hkdf_label = get_tls_hkdf_label(32, label_string, context_hash);

    return hkdf_expand(secret, hkdf_label);
  }



}
