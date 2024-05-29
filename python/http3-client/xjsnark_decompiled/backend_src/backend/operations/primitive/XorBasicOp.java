package backend.operations.primitive;

import backend.eval.Instruction;
import backend.structure.Wire;
import java.math.BigInteger;
import util.Util;

public class XorBasicOp extends BasicOp {
   public XorBasicOp(Wire w1, Wire w2, Wire output, String... desc) {
      super(new Wire[]{w1, w2}, new Wire[]{output}, desc);
   }

   public String getOpcode() {
      return "xor";
   }

   public void checkInputs(BigInteger[] assignment) {
      super.checkInputs(assignment);
      boolean check = Util.isBinary(assignment[this.inputs[0].getWireId()]) && Util.isBinary(assignment[this.inputs[1].getWireId()]);
      if (!check) {
         System.err.println("Error - Input(s) to XOR are not binary. " + this);
         throw new RuntimeException("Error During Evaluation");
      }
   }

   public void compute(BigInteger[] assignment) {
      assignment[this.outputs[0].getWireId()] = assignment[this.inputs[0].getWireId()].xor(assignment[this.inputs[1].getWireId()]);
   }

   public boolean equals(Object obj) {
      if (this == obj) {
         return true;
      } else if (!(obj instanceof XorBasicOp)) {
         return false;
      } else {
         XorBasicOp op = (XorBasicOp)obj;
         boolean check1 = this.inputs[0].equals(op.inputs[0]) && this.inputs[1].equals(op.inputs[1]);
         boolean check2 = this.inputs[1].equals(op.inputs[0]) && this.inputs[0].equals(op.inputs[1]);
         return check1 || check2;
      }
   }

   public int getNumMulGates() {
      return 1;
   }

   public Instruction copy(Wire[] wireArray) {
      Wire in = wireArray[this.inputs[0].getWireId()];
      Wire in2 = wireArray[this.inputs[1].getWireId()];
      Wire out = this.outputs[0].copy();
      wireArray[out.getWireId()] = out;
      return new XorBasicOp(in, in2, out, new String[]{this.desc});
   }
}
