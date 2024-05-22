package xjsnark.util_and_sha;

/*Generated by MPS */

import backend.auxTypes.UnsignedInteger;
import backend.structure.CircuitGenerator;
import backend.auxTypes.Bit;
import backend.auxTypes.ConditionalScopeTracker;
import java.math.BigInteger;
import backend.auxTypes.SmartMemory;

public class SHA2 {


  // This class is built on the example sha256 file from xJsnark
  // which had code for one SHA2 compression function.
  // The rest of the code extends this to add padding and other optimizations such as:
  // - calling SHA with a given H-state as checkpoint
  // - reusing SHA state when calling SHA on a string and that string's prefix

  // The constant definitions and the compression function are taken from the xJsnark example
  // with only slight modifications.
  public static final long[] K_CONST = {1116352408L, 1899447441L, 3049323471L, 3921009573L, 961987163L, 1508970993L, 2453635748L, 2870763221L, 3624381080L, 310598401L, 607225278L, 1426881987L, 1925078388L, 2162078206L, 2614888103L, 3248222580L, 3835390401L, 4022224774L, 264347078L, 604807628L, 770255983L, 1249150122L, 1555081692L, 1996064986L, 2554220882L, 2821834349L, 2952996808L, 3210313671L, 3336571891L, 3584528711L, 113926993L, 338241895L, 666307205L, 773529912L, 1294757372L, 1396182291L, 1695183700L, 1986661051L, 2177026350L, 2456956037L, 2730485921L, 2820302411L, 3259730800L, 3345764771L, 3516065817L, 3600352804L, 4094571909L, 275423344L, 430227734L, 506948616L, 659060556L, 883997877L, 958139571L, 1322822218L, 1537002063L, 1747873779L, 1955562222L, 2024104815L, 2227730452L, 2361852424L, 2428436474L, 2756734187L, 3204031479L, 3329325298L};

  public static final long[] H_CONST = {1779033703L, 3144134277L, 1013904242L, 2773480762L, 1359893119L, 2600822924L, 528734635L, 1541459225L};

  // This function is from the xJsnark example file
  // It performs one compression of SHA when given an input of length 16 x 32 = 256 
  // and a "checkpoint" state H
  private static UnsignedInteger[] sha2_compression(UnsignedInteger[] input, UnsignedInteger[] H) {
    if (input.length != 16) {
      throw new IllegalArgumentException("This method only accepts 16 32-bit words as inputs");
    }
    if (H.length != 8) {
      throw new IllegalArgumentException("This method only accepts 16 32-bit words as h_prev");
    }

    UnsignedInteger[] words = (UnsignedInteger[]) UnsignedInteger.createZeroArray(CircuitGenerator.__getActiveCircuitGenerator(), new int[]{64}, 32);
    UnsignedInteger a = H[0].copy(32);
    UnsignedInteger b = H[1].copy(32);
    UnsignedInteger c = H[2].copy(32);
    UnsignedInteger d = H[3].copy(32);
    UnsignedInteger e = H[4].copy(32);
    UnsignedInteger f = H[5].copy(32);
    UnsignedInteger g = H[6].copy(32);
    UnsignedInteger h = H[7].copy(32);

    for (int j = 0; j < 16; j++) {
      words[j].assign(input[j], 32);
    }

    for (int j = 16; j < 64; j++) {
      UnsignedInteger s0 = rotateRight(words[j - 15].copy(32), 7).xorBitwise(rotateRight(words[j - 15].copy(32), 18)).xorBitwise((words[j - 15].shiftRight(3))).copy(32);
      UnsignedInteger s1 = rotateRight(words[j - 2].copy(32), 17).xorBitwise(rotateRight(words[j - 2].copy(32), 19)).xorBitwise((words[j - 2].shiftRight(10))).copy(32);
      words[j].assign(words[j - 16].add(s0).add(words[j - 7]).add(s1), 32);
    }

    for (int j = 0; j < 64; j++) {
      UnsignedInteger s0 = rotateRight(a.copy(32), 2).xorBitwise(rotateRight(a.copy(32), 13)).xorBitwise(rotateRight(a.copy(32), 22)).copy(32);
      UnsignedInteger maj = (a.andBitwise(b)).xorBitwise((a.andBitwise(c))).xorBitwise((b.andBitwise(c))).copy(32);
      UnsignedInteger t2 = s0.add(maj).copy(32);


      UnsignedInteger s1 = rotateRight(e.copy(32), 6).xorBitwise(rotateRight(e.copy(32), 11)).xorBitwise(rotateRight(e.copy(32), 25)).copy(32);
      UnsignedInteger ch = e.andBitwise(f).xorBitwise(e.invBits().andBitwise(g)).copy(32);
      // the uint_32(.) call is to convert from java type to xjsnark type 
      UnsignedInteger t1 = h.add(s1).add(ch).add(UnsignedInteger.instantiateFrom(32, K_CONST[j])).add(words[j]).copy(32);
      h.assign(g, 32);
      g.assign(f, 32);
      f.assign(e, 32);
      e.assign(d.add(t1), 32);
      d.assign(c, 32);
      c.assign(b, 32);
      b.assign(a, 32);
      a.assign(t1.add(t2), 32);
    }

    H[0].assign(H[0].add(a), 32);
    H[1].assign(H[1].add(b), 32);
    H[2].assign(H[2].add(c), 32);
    H[3].assign(H[3].add(d), 32);
    H[4].assign(H[4].add(e), 32);
    H[5].assign(H[5].add(f), 32);
    H[6].assign(H[6].add(g), 32);
    H[7].assign(H[7].add(h), 32);

    return H;

  }

  public static UnsignedInteger rotateRight(UnsignedInteger in, int r) {
    return (in.shiftRight(r)).orBitwise((in.shiftLeft((32 - r))));
  }

  // Calling SH with variants based on whether we need to pad
  // and whether we have a H_state as checkpoint

  // ************************************************************
  // This is the main SHA calling function.
  public static UnsignedInteger[] sha2(UnsignedInteger[] input) {

    if (input.length == 64) {
      return sha2_512_length(input);
    }

    UnsignedInteger[] padded_input = (UnsignedInteger[]) UnsignedInteger.createZeroArray(CircuitGenerator.__getActiveCircuitGenerator(), new int[]{32}, 8);
    padded_input = padded_sha_input(input);

    UnsignedInteger[] input_in_32 = Util.convert_8_to_32(padded_input);

    if (input_in_32.length % 16 != 0) {
      throw new IllegalArgumentException("Padded sha must be a multiple of 512");
    }


    int num_blocks = input_in_32.length / 16;

    UnsignedInteger[] h_value = UnsignedInteger.instantiateFrom(32, H_CONST);

    UnsignedInteger[] block = (UnsignedInteger[]) UnsignedInteger.createZeroArray(CircuitGenerator.__getActiveCircuitGenerator(), new int[]{16}, 32);
    for (int i = 0; i < num_blocks; i++) {
      for (int j = 0; j < 16; j++) {
        block[j].assign(input_in_32[i * 16 + j], 32);
      }
      h_value = sha2_compression(block, h_value);
    }

    return Util.convert_32_to_8(h_value);
  }

  // Function for when the input is of length 512 bits (one SHA block)
  // This just has the pad and other state values hardcoded and is slightly smaller
  // Insert results - ??
  public static UnsignedInteger[] sha2_512_length(UnsignedInteger[] input) {
    UnsignedInteger[] pad = UnsignedInteger.instantiateFrom(8, PAD_FOR_512);

    UnsignedInteger[] h_value = UnsignedInteger.instantiateFrom(32, H_CONST);

    h_value = sha2_compression(Util.convert_8_to_32(input), h_value);

    h_value = compression_with_words(UnsignedInteger.instantiateFrom(32, PAD_FOR_512), h_value, UnsignedInteger.instantiateFrom(32, WORDS_FOR_512_PAD));

    return Util.convert_32_to_8(h_value);

  }


  public static UnsignedInteger[] sha2_no_pad_with_checkpoint(UnsignedInteger[] input, UnsignedInteger[] H) {

    UnsignedInteger[] input_in_32 = Util.convert_8_to_32(input);

    if (input_in_32.length % 16 != 0) {
      throw new IllegalArgumentException("Padded sha must be a multiple of 512");
    }

    int num_blocks = input_in_32.length / 16;

    UnsignedInteger[] h_value = UnsignedInteger.instantiateFrom(32, H);

    UnsignedInteger[] block = (UnsignedInteger[]) UnsignedInteger.createZeroArray(CircuitGenerator.__getActiveCircuitGenerator(), new int[]{16}, 32);
    for (int i = 0; i < num_blocks; i++) {
      for (int j = 0; j < 16; j++) {
        block[j].assign(input_in_32[i * 16 + j], 32);
      }
      h_value = sha2_compression(block, h_value);
    }

    return Util.convert_32_to_8(h_value);
  }


  public static UnsignedInteger[] sha2_no_pad(UnsignedInteger[] input) {

    UnsignedInteger[] input_in_32 = Util.convert_8_to_32(input);

    if (input_in_32.length % 16 != 0) {
      throw new IllegalArgumentException("Padded sha must be a multiple of 512");
    }

    int num_blocks = input_in_32.length / 16;

    UnsignedInteger[] h_value = UnsignedInteger.instantiateFrom(32, H_CONST);

    UnsignedInteger[] block = (UnsignedInteger[]) UnsignedInteger.createZeroArray(CircuitGenerator.__getActiveCircuitGenerator(), new int[]{16}, 32);
    for (int i = 0; i < num_blocks; i++) {
      for (int j = 0; j < 16; j++) {
        block[j].assign(input_in_32[i * 16 + j], 32);
      }
      h_value = sha2_compression(block, h_value);
    }
    return h_value;
  }


  // Performs the specified number of sha2 compression calls on the given input
  public static UnsignedInteger[] perform_compressions(UnsignedInteger[] input, UnsignedInteger num_compressions) {

    return perform_compressions(input, num_compressions.copy(8), UnsignedInteger.instantiateFrom(32, H_CONST));
  }

  // The above, but with an arbitary H-state
  public static UnsignedInteger[] perform_compressions(UnsignedInteger[] input, UnsignedInteger num_compressions, UnsignedInteger[] H_checkpoint) {

    UnsignedInteger[] h_value = UnsignedInteger.instantiateFrom(32, H_checkpoint);

    UnsignedInteger[] block = (UnsignedInteger[]) UnsignedInteger.createZeroArray(CircuitGenerator.__getActiveCircuitGenerator(), new int[]{64}, 8);

    // Iterate for the maximum possible times that may be required depending on the maximum input length 
    // NOTE: input must be long enough to support maximum number of iterations 
    int max_compressions = (input.length) / 64;
    for (int i = 0; i < max_compressions; i++) {
      {
        Bit bit_a0i0sb = UnsignedInteger.instantiateFrom(8, i).isLessThan(num_compressions).copy();
        boolean c_a0i0sb = CircuitGenerator.__getActiveCircuitGenerator().__checkConstantState(bit_a0i0sb);
        if (c_a0i0sb) {
          if (bit_a0i0sb.getConstantValue()) {
            for (int j = 0; j < 64; j++) {
              block[j].assign(input[i * 64 + j], 8);
            }
            h_value = sha2_compression(Util.convert_8_to_32(block), h_value);
          } else {

          }
        } else {
          ConditionalScopeTracker.pushMain();
          ConditionalScopeTracker.push(bit_a0i0sb);
          for (int j = 0; j < 64; j++) {
            block[j].assign(input[i * 64 + j], 8);
          }
          h_value = sha2_compression(Util.convert_8_to_32(block), h_value);

          ConditionalScopeTracker.pop();

          ConditionalScopeTracker.push(new Bit(true));

          ConditionalScopeTracker.pop();
          ConditionalScopeTracker.popMain();
        }

      }
    }

    return h_value;
  }



  // The next two variables were used for a minor optimization for when the padded input is just one block length
  // which is 512 bits in SHA2
  public static final long[] PAD_FOR_512 = {2147483648L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 512L};

  public static final long[] WORDS_FOR_512_PAD = {2147483648L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 512L, 2147483648L, 20971520L, 2117632L, 20616L, 570427392L, 575995924L, 84449090L, 2684354592L, 1518862336L, 6067200L, 1496221L, 4202700544L, 3543279056L, 291985753L, 4142317530L, 3003913545L, 145928272L, 2642168871L, 216179603L, 2296832490L, 2771075893L, 1738633033L, 3610378607L, 1324035729L, 1572820453L, 2397971253L, 3803995842L, 2822718356L, 1168996599L, 921948365L, 3650881000L, 2958106055L, 1773959876L, 3172022107L, 3820646885L, 991993842L, 419360279L, 3797604839L, 322392134L, 85264541L, 1326255876L, 640108622L, 822159570L, 3328750644L, 1107837388L, 1657999800L, 3852183409L, 2242356356L};


  // Function to return the hash of the empty string
  public static UnsignedInteger[] hash_of_empty() {
    int[] HASH_OF_EMPTY = {227, 176, 196, 66, 152, 252, 28, 20, 154, 251, 244, 200, 153, 111, 185, 36, 39, 174, 65, 228, 100, 155, 147, 76, 164, 149, 153, 27, 120, 82, 184, 85};
    return UnsignedInteger.instantiateFrom(8, HASH_OF_EMPTY);
  }

  // //////////////////////////////////////////////////////////////////////////////////////////////////////////////////
  // The following code is written to add support for padding 
  // and the optimizations used in SHA explained at the top of this file.


  // Returns the input appended with the pad
  public static UnsignedInteger[] padded_sha_input(UnsignedInteger[] input) {
    int bit_length = 8 * input.length;
    int last_block_length = bit_length % 512;

    int num_bytes_left = (512 - last_block_length) / 8;
    if (num_bytes_left <= 8) {
      num_bytes_left += 64;
    }

    //  8 bytes go for the length 
    UnsignedInteger[] one_and_zeros = (UnsignedInteger[]) UnsignedInteger.createZeroArray(CircuitGenerator.__getActiveCircuitGenerator(), new int[]{num_bytes_left - 8}, 8);
    one_and_zeros[0].assign(UnsignedInteger.instantiateFrom(8, 128), 8);

    for (int i = 1; i < one_and_zeros.length; i++) {
      one_and_zeros[i].assign(new UnsignedInteger(8, new BigInteger("0")), 8);
    }

    UnsignedInteger[] length_pad = (UnsignedInteger[]) UnsignedInteger.createZeroArray(CircuitGenerator.__getActiveCircuitGenerator(), new int[]{8}, 8);


    long bit_length_64 = bit_length;

    for (int i = 0; i < 8; i++) {
      length_pad[i].assign(UnsignedInteger.instantiateFrom(8, bit_length_64 >> (8 * (7 - i))), 8);
    }

    UnsignedInteger[][] arrays_to_concat = {input, one_and_zeros, length_pad};

    return Util.concat(arrays_to_concat);
  }


  // Returns the length of the pad required for a given input length
  public static UnsignedInteger get_pad_length(UnsignedInteger input_length) {

    UnsignedInteger last_block_length = UnsignedInteger.instantiateFrom(8, input_length.mod(UnsignedInteger.instantiateFrom(8, 64))).copy(8);

    UnsignedInteger pad_length = new UnsignedInteger(8, new BigInteger("0"));

    {
      Bit bit_f0qc = last_block_length.isLessThanOrEquals(UnsignedInteger.instantiateFrom(8, 55)).copy();
      boolean c_f0qc = CircuitGenerator.__getActiveCircuitGenerator().__checkConstantState(bit_f0qc);
      if (c_f0qc) {
        if (bit_f0qc.getConstantValue()) {
          pad_length.assign(UnsignedInteger.instantiateFrom(8, 64).subtract(last_block_length), 8);
        } else {
          pad_length.assign(UnsignedInteger.instantiateFrom(8, 128).subtract(last_block_length), 8);

        }
      } else {
        ConditionalScopeTracker.pushMain();
        ConditionalScopeTracker.push(bit_f0qc);
        pad_length.assign(UnsignedInteger.instantiateFrom(8, 64).subtract(last_block_length), 8);

        ConditionalScopeTracker.pop();

        ConditionalScopeTracker.push(new Bit(true));

        pad_length.assign(UnsignedInteger.instantiateFrom(8, 128).subtract(last_block_length), 8);
        ConditionalScopeTracker.pop();
        ConditionalScopeTracker.popMain();
      }

    }

    return pad_length;
  }

  // Returns the actual pad required for a given input length
  public static UnsignedInteger[] get_pad_from_length_in_bytes(UnsignedInteger length) {

    UnsignedInteger pad_length = get_pad_length(length.copy(16)).copy(8);

    UnsignedInteger[] input_len_in_bits = Util.convert_64_to_8(UnsignedInteger.instantiateFrom(64, length).mul(UnsignedInteger.instantiateFrom(64, 8)).copy(64));

    SmartMemory<UnsignedInteger> inputLenRam;
    inputLenRam = new SmartMemory(input_len_in_bits, UnsignedInteger.__getClassRef(), new Object[]{"8"});

    // It'll be less than 72 but 128 mades it an even multiple of 64 
    UnsignedInteger[] pad = (UnsignedInteger[]) UnsignedInteger.createZeroArray(CircuitGenerator.__getActiveCircuitGenerator(), new int[]{128}, 8);

    pad[0].assign(UnsignedInteger.instantiateFrom(8, 128), 8);

    UnsignedInteger counter = UnsignedInteger.instantiateFrom(8, 0).copy(8);
    for (int i = 0; i < 72; i++) {
      {
        Bit bit_a0o0tc = UnsignedInteger.instantiateFrom(8, i).isLessThan(pad_length).copy();
        boolean c_a0o0tc = CircuitGenerator.__getActiveCircuitGenerator().__checkConstantState(bit_a0o0tc);
        if (c_a0o0tc) {
          if (bit_a0o0tc.getConstantValue()) {
            {
              Bit bit_a0a0a2a0a41a17 = (UnsignedInteger.instantiateFrom(8, i).add(UnsignedInteger.instantiateFrom(8, 8)).isGreaterThanOrEquals(pad_length)).copy();
              boolean c_a0a0a2a0a41a17 = CircuitGenerator.__getActiveCircuitGenerator().__checkConstantState(bit_a0a0a2a0a41a17);
              if (c_a0a0a2a0a41a17) {
                if (bit_a0a0a2a0a41a17.getConstantValue()) {
                  pad[i].assign(inputLenRam.read(counter), 8);
                  counter.assign(counter.add(UnsignedInteger.instantiateFrom(8, 1)), 8);
                } else {

                }
              } else {
                ConditionalScopeTracker.pushMain();
                ConditionalScopeTracker.push(bit_a0a0a2a0a41a17);
                pad[i].assign(inputLenRam.read(counter), 8);
                counter.assign(counter.add(UnsignedInteger.instantiateFrom(8, 1)), 8);

                ConditionalScopeTracker.pop();

                ConditionalScopeTracker.push(new Bit(true));

                ConditionalScopeTracker.pop();
                ConditionalScopeTracker.popMain();
              }

            }
          } else {

          }
        } else {
          ConditionalScopeTracker.pushMain();
          ConditionalScopeTracker.push(bit_a0o0tc);
          {
            Bit bit_a0a0o0tc = (UnsignedInteger.instantiateFrom(8, i).add(UnsignedInteger.instantiateFrom(8, 8)).isGreaterThanOrEquals(pad_length)).copy();
            boolean c_a0a0o0tc = CircuitGenerator.__getActiveCircuitGenerator().__checkConstantState(bit_a0a0o0tc);
            if (c_a0a0o0tc) {
              if (bit_a0a0o0tc.getConstantValue()) {
                pad[i].assign(inputLenRam.read(counter), 8);
                counter.assign(counter.add(UnsignedInteger.instantiateFrom(8, 1)), 8);
              } else {

              }
            } else {
              ConditionalScopeTracker.pushMain();
              ConditionalScopeTracker.push(bit_a0a0o0tc);
              pad[i].assign(inputLenRam.read(counter), 8);
              counter.assign(counter.add(UnsignedInteger.instantiateFrom(8, 1)), 8);

              ConditionalScopeTracker.pop();

              ConditionalScopeTracker.push(new Bit(true));

              ConditionalScopeTracker.pop();
              ConditionalScopeTracker.popMain();
            }

          }

          ConditionalScopeTracker.pop();

          ConditionalScopeTracker.push(new Bit(true));

          ConditionalScopeTracker.pop();
          ConditionalScopeTracker.popMain();
        }

      }
    }

    return pad;
  }


  // ///////////////////////// Functions for computing the hash of a string AND a prefix of that string
  // without redoing the entire computation.
  // That is, we use the H_state value of the compression function of the blocks that are common
  // to both the string and its prefix.

  // the full string ~ "full"
  // the prefix string ~ "prefix"

  // H_checkpoint - H state that is common to both prefix and full string
  // full_length - the total length of the full string
  // prefix_length - the length of the prefix string
  // full_tail - the portion of the full string past the checkpoint block
  // full_tail_length
  // prefix_tail_length - the length of the prefix of full_tail that belongs to the prefix string
  public static UnsignedInteger[][] double_sha_from_checkpoint(UnsignedInteger[] H_checkpoint, UnsignedInteger full_length, UnsignedInteger prefix_length, UnsignedInteger[] full_tail_string, UnsignedInteger full_tail_length, UnsignedInteger prefix_tail_length) {

    UnsignedInteger[] prefix_output = sha2_of_tail(full_tail_string, prefix_tail_length.copy(8), prefix_length.copy(16), H_checkpoint);

    UnsignedInteger[] full_output = sha2_of_tail(full_tail_string, full_tail_length.copy(8), full_length.copy(16), H_checkpoint);

    return new UnsignedInteger[][]{prefix_output, full_output};
  }

  // This is the same as the above function, but does not start with a checkpoint.
  // Instead of a H_checkpoint being provided, the full string is given.
  // The required number of compressions is performed to obtain H_checkpoint
  public static UnsignedInteger[][] double_sha(UnsignedInteger[] full_string, UnsignedInteger full_length, UnsignedInteger prefix_length, UnsignedInteger[] full_tail, UnsignedInteger full_tail_length, UnsignedInteger prefix_tail_length) {

    UnsignedInteger num_common_blocks = UnsignedInteger.instantiateFrom(8, prefix_length.div(UnsignedInteger.instantiateFrom(8, 64))).copy(8);

    // Obtain H_checkpoint by performing compressions on the full string 
    // up to the number of SHA blocks that are common to both full and prefix 
    UnsignedInteger[] H_checkpoint = perform_compressions(full_string, num_common_blocks.copy(8));

    UnsignedInteger[] prefix_output = sha2_of_tail(full_tail, prefix_tail_length.copy(8), prefix_length.copy(16), H_checkpoint);

    UnsignedInteger[] full_output = sha2_of_tail(full_tail, full_tail_length.copy(8), full_length.copy(16), H_checkpoint);

    return new UnsignedInteger[][]{prefix_output, full_output};
  }


  // This function takes as input a tail string that is of length less than 128 bytes
  // and a H_checkpoint
  // and computes the hash of the tail with the checkpoint.
  // The full string's length is given to calculate the pad.
  public static UnsignedInteger[] sha2_of_tail(UnsignedInteger[] tail, UnsignedInteger tail_length, UnsignedInteger full_length, UnsignedInteger[] H_checkpoint) {

    // Calculate the pad 
    UnsignedInteger pad_len_in_bytes = get_pad_length(full_length.copy(16)).copy(8);
    UnsignedInteger[] pad = get_pad_from_length_in_bytes(full_length.copy(16));

    SmartMemory<UnsignedInteger> padRam;
    padRam = new SmartMemory(pad, UnsignedInteger.__getClassRef(), new Object[]{"8"});

    // tail_with_pad = tail || pad 
    UnsignedInteger[] tail_with_pad = (UnsignedInteger[]) UnsignedInteger.createZeroArray(CircuitGenerator.__getActiveCircuitGenerator(), new int[]{128}, 8);

    // This is either 1 or 2 depending on the pad length 
    UnsignedInteger num_compressions = (tail_length.add(pad_len_in_bytes)).div(UnsignedInteger.instantiateFrom(8, 64)).copy(8);

    for (int i = 0; i < 128; i++) {
      {
        Bit bit_a0o0wd = UnsignedInteger.instantiateFrom(8, i).isLessThan(tail_length).copy();
        boolean c_a0o0wd = CircuitGenerator.__getActiveCircuitGenerator().__checkConstantState(bit_a0o0wd);
        if (c_a0o0wd) {
          if (bit_a0o0wd.getConstantValue()) {
            tail_with_pad[i].assign(tail[i], 8);
          } else {
            {
              Bit bit_a0a0a0a2a0a41a001 = UnsignedInteger.instantiateFrom(8, i).subtract(UnsignedInteger.instantiateFrom(8, tail_length)).isLessThan(UnsignedInteger.instantiateFrom(8, pad_len_in_bytes)).copy();
              boolean c_a0a0a0a2a0a41a001 = CircuitGenerator.__getActiveCircuitGenerator().__checkConstantState(bit_a0a0a0a2a0a41a001);
              if (c_a0a0a0a2a0a41a001) {
                if (bit_a0a0a0a2a0a41a001.getConstantValue()) {
                  tail_with_pad[i].assign(padRam.read(UnsignedInteger.instantiateFrom(8, i).subtract(tail_length)), 8);
                } else {
                  tail_with_pad[i].assign(UnsignedInteger.instantiateFrom(8, 0), 8);

                }
              } else {
                ConditionalScopeTracker.pushMain();
                ConditionalScopeTracker.push(bit_a0a0a0a2a0a41a001);
                tail_with_pad[i].assign(padRam.read(UnsignedInteger.instantiateFrom(8, i).subtract(tail_length)), 8);

                ConditionalScopeTracker.pop();

                ConditionalScopeTracker.push(new Bit(true));

                tail_with_pad[i].assign(UnsignedInteger.instantiateFrom(8, 0), 8);
                ConditionalScopeTracker.pop();
                ConditionalScopeTracker.popMain();
              }

            }

          }
        } else {
          ConditionalScopeTracker.pushMain();
          ConditionalScopeTracker.push(bit_a0o0wd);
          tail_with_pad[i].assign(tail[i], 8);

          ConditionalScopeTracker.pop();

          ConditionalScopeTracker.push(new Bit(true));

          {
            Bit bit_a0a0a41a001_0 = UnsignedInteger.instantiateFrom(8, i).subtract(UnsignedInteger.instantiateFrom(8, tail_length)).isLessThan(UnsignedInteger.instantiateFrom(8, pad_len_in_bytes)).copy();
            boolean c_a0a0a41a001_0 = CircuitGenerator.__getActiveCircuitGenerator().__checkConstantState(bit_a0a0a41a001_0);
            if (c_a0a0a41a001_0) {
              if (bit_a0a0a41a001_0.getConstantValue()) {
                tail_with_pad[i].assign(padRam.read(UnsignedInteger.instantiateFrom(8, i).subtract(tail_length)), 8);
              } else {
                tail_with_pad[i].assign(UnsignedInteger.instantiateFrom(8, 0), 8);

              }
            } else {
              ConditionalScopeTracker.pushMain();
              ConditionalScopeTracker.push(bit_a0a0a41a001_0);
              tail_with_pad[i].assign(padRam.read(UnsignedInteger.instantiateFrom(8, i).subtract(tail_length)), 8);

              ConditionalScopeTracker.pop();

              ConditionalScopeTracker.push(new Bit(true));

              tail_with_pad[i].assign(UnsignedInteger.instantiateFrom(8, 0), 8);
              ConditionalScopeTracker.pop();
              ConditionalScopeTracker.popMain();
            }

          }
          ConditionalScopeTracker.pop();
          ConditionalScopeTracker.popMain();
        }

      }
    }

    UnsignedInteger[] output;

    UnsignedInteger[] H_value = UnsignedInteger.instantiateFrom(32, H_checkpoint);

    UnsignedInteger[] block = (UnsignedInteger[]) UnsignedInteger.createZeroArray(CircuitGenerator.__getActiveCircuitGenerator(), new int[]{64}, 8);

    // Iterate for the maximum possible times, which is 2. 
    // NOTE: input must be long enough to support maximum number of iterations 
    for (int i = 0; i < 2; i++) {
      {
        Bit bit_a0y0wd = UnsignedInteger.instantiateFrom(8, i).isLessThan(num_compressions).copy();
        boolean c_a0y0wd = CircuitGenerator.__getActiveCircuitGenerator().__checkConstantState(bit_a0y0wd);
        if (c_a0y0wd) {
          if (bit_a0y0wd.getConstantValue()) {
            for (int j = 0; j < 64; j++) {
              block[j].assign(tail_with_pad[i * 64 + j], 8);
            }

            H_value = sha2_compression(Util.convert_8_to_32(block), H_value);
          } else {

          }
        } else {
          ConditionalScopeTracker.pushMain();
          ConditionalScopeTracker.push(bit_a0y0wd);
          for (int j = 0; j < 64; j++) {
            block[j].assign(tail_with_pad[i * 64 + j], 8);
          }

          H_value = sha2_compression(Util.convert_8_to_32(block), H_value);

          ConditionalScopeTracker.pop();

          ConditionalScopeTracker.push(new Bit(true));

          ConditionalScopeTracker.pop();
          ConditionalScopeTracker.popMain();
        }

      }
    }

    output = H_value;

    return Util.convert_32_to_8(output);
  }

  // Given an input string, a length and a final block
  // this function returns the hash of the first l bytes of the input
  // The final block is provided as auxiliary input to optimize the final circuit.
  public static UnsignedInteger[] sha2_of_prefix(UnsignedInteger[] input, UnsignedInteger tr_len_in_bytes, UnsignedInteger[] last_block) {

    UnsignedInteger[] output = (UnsignedInteger[]) UnsignedInteger.createZeroArray(CircuitGenerator.__getActiveCircuitGenerator(), new int[]{32}, 8);

    UnsignedInteger last_block_len = UnsignedInteger.instantiateFrom(8, tr_len_in_bytes.mod(UnsignedInteger.instantiateFrom(16, 64))).copy(8);

    UnsignedInteger pad_len_in_bytes = get_pad_length(tr_len_in_bytes.copy(16)).copy(8);
    UnsignedInteger[] pad = get_pad_from_length_in_bytes(tr_len_in_bytes.copy(16));

    SmartMemory<UnsignedInteger> padRam;
    padRam = new SmartMemory(pad, UnsignedInteger.__getClassRef(), new Object[]{"8"});

    UnsignedInteger num_base_compressions = UnsignedInteger.instantiateFrom(8, tr_len_in_bytes.div(UnsignedInteger.instantiateFrom(16, 64))).copy(8);

    UnsignedInteger[] H_value_base = perform_compressions(input, num_base_compressions.copy(8));

    UnsignedInteger[] last_blocks_padded = (UnsignedInteger[]) UnsignedInteger.createZeroArray(CircuitGenerator.__getActiveCircuitGenerator(), new int[]{128}, 8);

    UnsignedInteger[] last_block_padded = (UnsignedInteger[]) UnsignedInteger.createZeroArray(CircuitGenerator.__getActiveCircuitGenerator(), new int[]{64}, 8);


    {
      Bit bit_u0be = pad_len_in_bytes.isGreaterThan(UnsignedInteger.instantiateFrom(8, 64)).copy();
      boolean c_u0be = CircuitGenerator.__getActiveCircuitGenerator().__checkConstantState(bit_u0be);
      if (c_u0be) {
        if (bit_u0be.getConstantValue()) {

          for (int i = 0; i < 64; i++) {
            {
              Bit bit_a0b0a0a2a02a501 = UnsignedInteger.instantiateFrom(8, i).isLessThan(last_block_len).copy();
              boolean c_a0b0a0a2a02a501 = CircuitGenerator.__getActiveCircuitGenerator().__checkConstantState(bit_a0b0a0a2a02a501);
              if (c_a0b0a0a2a02a501) {
                if (bit_a0b0a0a2a02a501.getConstantValue()) {
                  last_blocks_padded[i].assign(last_block[i], 8);
                } else {
                  last_blocks_padded[i].assign(padRam.read(UnsignedInteger.instantiateFrom(8, i).subtract(last_block_len)), 8);

                }
              } else {
                ConditionalScopeTracker.pushMain();
                ConditionalScopeTracker.push(bit_a0b0a0a2a02a501);
                last_blocks_padded[i].assign(last_block[i], 8);

                ConditionalScopeTracker.pop();

                ConditionalScopeTracker.push(new Bit(true));

                last_blocks_padded[i].assign(padRam.read(UnsignedInteger.instantiateFrom(8, i).subtract(last_block_len)), 8);
                ConditionalScopeTracker.pop();
                ConditionalScopeTracker.popMain();
              }

            }
          }

          for (int i = 64; i < 128; i++) {
            last_blocks_padded[i].assign(padRam.read(UnsignedInteger.instantiateFrom(8, i).subtract(last_block_len)), 8);
          }

          output = sha2_no_pad_with_checkpoint(last_blocks_padded, H_value_base);

        } else {
          for (int i = 0; i < 64; i++) {
            {
              Bit bit_a0a0a0a0a2a02a501 = UnsignedInteger.instantiateFrom(8, i).isLessThan(last_block_len).copy();
              boolean c_a0a0a0a0a2a02a501 = CircuitGenerator.__getActiveCircuitGenerator().__checkConstantState(bit_a0a0a0a0a2a02a501);
              if (c_a0a0a0a0a2a02a501) {
                if (bit_a0a0a0a0a2a02a501.getConstantValue()) {
                  last_block_padded[i].assign(last_block[i], 8);
                } else {
                  last_block_padded[i].assign(padRam.read(UnsignedInteger.instantiateFrom(8, i).subtract(last_block_len)), 8);

                }
              } else {
                ConditionalScopeTracker.pushMain();
                ConditionalScopeTracker.push(bit_a0a0a0a0a2a02a501);
                last_block_padded[i].assign(last_block[i], 8);

                ConditionalScopeTracker.pop();

                ConditionalScopeTracker.push(new Bit(true));

                last_block_padded[i].assign(padRam.read(UnsignedInteger.instantiateFrom(8, i).subtract(last_block_len)), 8);
                ConditionalScopeTracker.pop();
                ConditionalScopeTracker.popMain();
              }

            }
          }

          output = sha2_no_pad_with_checkpoint(last_block_padded, H_value_base);


        }
      } else {
        ConditionalScopeTracker.pushMain();
        ConditionalScopeTracker.push(bit_u0be);

        for (int i = 0; i < 64; i++) {
          {
            Bit bit_a0b0u0be = UnsignedInteger.instantiateFrom(8, i).isLessThan(last_block_len).copy();
            boolean c_a0b0u0be = CircuitGenerator.__getActiveCircuitGenerator().__checkConstantState(bit_a0b0u0be);
            if (c_a0b0u0be) {
              if (bit_a0b0u0be.getConstantValue()) {
                last_blocks_padded[i].assign(last_block[i], 8);
              } else {
                last_blocks_padded[i].assign(padRam.read(UnsignedInteger.instantiateFrom(8, i).subtract(last_block_len)), 8);

              }
            } else {
              ConditionalScopeTracker.pushMain();
              ConditionalScopeTracker.push(bit_a0b0u0be);
              last_blocks_padded[i].assign(last_block[i], 8);

              ConditionalScopeTracker.pop();

              ConditionalScopeTracker.push(new Bit(true));

              last_blocks_padded[i].assign(padRam.read(UnsignedInteger.instantiateFrom(8, i).subtract(last_block_len)), 8);
              ConditionalScopeTracker.pop();
              ConditionalScopeTracker.popMain();
            }

          }
        }

        for (int i = 64; i < 128; i++) {
          last_blocks_padded[i].assign(padRam.read(UnsignedInteger.instantiateFrom(8, i).subtract(last_block_len)), 8);
        }

        output = sha2_no_pad_with_checkpoint(last_blocks_padded, H_value_base);


        ConditionalScopeTracker.pop();

        ConditionalScopeTracker.push(new Bit(true));

        for (int i = 0; i < 64; i++) {
          {
            Bit bit_a0a0a02a501_0 = UnsignedInteger.instantiateFrom(8, i).isLessThan(last_block_len).copy();
            boolean c_a0a0a02a501_0 = CircuitGenerator.__getActiveCircuitGenerator().__checkConstantState(bit_a0a0a02a501_0);
            if (c_a0a0a02a501_0) {
              if (bit_a0a0a02a501_0.getConstantValue()) {
                last_block_padded[i].assign(last_block[i], 8);
              } else {
                last_block_padded[i].assign(padRam.read(UnsignedInteger.instantiateFrom(8, i).subtract(last_block_len)), 8);

              }
            } else {
              ConditionalScopeTracker.pushMain();
              ConditionalScopeTracker.push(bit_a0a0a02a501_0);
              last_block_padded[i].assign(last_block[i], 8);

              ConditionalScopeTracker.pop();

              ConditionalScopeTracker.push(new Bit(true));

              last_block_padded[i].assign(padRam.read(UnsignedInteger.instantiateFrom(8, i).subtract(last_block_len)), 8);
              ConditionalScopeTracker.pop();
              ConditionalScopeTracker.popMain();
            }

          }
        }

        output = sha2_no_pad_with_checkpoint(last_block_padded, H_value_base);

        ConditionalScopeTracker.pop();
        ConditionalScopeTracker.popMain();
      }

    }

    return output;
  }




  // Unused functions here

  public static UnsignedInteger[][] sha2_full_and_prefix(UnsignedInteger[] input, int prefix_length) {

    UnsignedInteger[] prefix = Util.get_prefix(input, prefix_length);

    UnsignedInteger[] prefix_padded = padded_sha_input(prefix);
    UnsignedInteger[] full_padded = padded_sha_input(input);

    int num_common_blocks = prefix_length / 64;
    int common_length = num_common_blocks * 64;

    UnsignedInteger[] common_blocks = Util.get_prefix(input, num_common_blocks * 64);

    UnsignedInteger[] prefix_tail = Util.get_tail(prefix_padded, common_length);
    UnsignedInteger[] full_tail = Util.get_tail(full_padded, common_length);

    UnsignedInteger[] H_checkpoint = sha2_no_pad(common_blocks);

    UnsignedInteger[] H_prefix = sha2_no_pad_with_checkpoint(prefix_tail, H_checkpoint);

    UnsignedInteger[] H_full = sha2_no_pad_with_checkpoint(full_tail, H_checkpoint);

    return new UnsignedInteger[][]{H_prefix, H_full};
  }



  private static UnsignedInteger[] compression_with_words(UnsignedInteger[] input, UnsignedInteger[] H, UnsignedInteger[] words) {
    if (input.length != 16) {
      throw new IllegalArgumentException("This method only accepts 16 32-bit words as inputs");
    }
    if (H.length != 8) {
      throw new IllegalArgumentException("This method only accepts 16 32-bit words as h_prev");
    }

    // uint_32[] H = uint_32(H_CONST);  

    UnsignedInteger a = H[0].copy(32);
    UnsignedInteger b = H[1].copy(32);
    UnsignedInteger c = H[2].copy(32);
    UnsignedInteger d = H[3].copy(32);
    UnsignedInteger e = H[4].copy(32);
    UnsignedInteger f = H[5].copy(32);
    UnsignedInteger g = H[6].copy(32);
    UnsignedInteger h = H[7].copy(32);

    for (int j = 0; j < 64; j++) {
      UnsignedInteger s0 = rotateRight(a.copy(32), 2).xorBitwise(rotateRight(a.copy(32), 13)).xorBitwise(rotateRight(a.copy(32), 22)).copy(32);
      UnsignedInteger maj = (a.andBitwise(b)).xorBitwise((a.andBitwise(c))).xorBitwise((b.andBitwise(c))).copy(32);
      UnsignedInteger t2 = s0.add(maj).copy(32);


      UnsignedInteger s1 = rotateRight(e.copy(32), 6).xorBitwise(rotateRight(e.copy(32), 11)).xorBitwise(rotateRight(e.copy(32), 25)).copy(32);
      UnsignedInteger ch = e.andBitwise(f).xorBitwise(e.invBits().andBitwise(g)).copy(32);
      // the uint_32(.) call is to convert from java type to xjsnark type 
      UnsignedInteger t1 = h.add(s1).add(ch).add(UnsignedInteger.instantiateFrom(32, K_CONST[j])).add(words[j]).copy(32);
      h.assign(g, 32);
      g.assign(f, 32);
      f.assign(e, 32);
      e.assign(d.add(t1), 32);
      d.assign(c, 32);
      c.assign(b, 32);
      b.assign(a, 32);
      a.assign(t1.add(t2), 32);
    }

    H[0].assign(H[0].add(a), 32);
    H[1].assign(H[1].add(b), 32);
    H[2].assign(H[2].add(c), 32);
    H[3].assign(H[3].add(d), 32);
    H[4].assign(H[4].add(e), 32);
    H[5].assign(H[5].add(f), 32);
    H[6].assign(H[6].add(g), 32);
    H[7].assign(H[7].add(h), 32);

    return H;
  }


}
