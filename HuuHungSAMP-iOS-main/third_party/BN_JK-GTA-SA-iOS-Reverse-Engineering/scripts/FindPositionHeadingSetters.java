//@category BN_JK


// BN_JK Reverse Engineering Research
// Autor e responsável pelo estudo: BN_JK
// Projeto: GTA San Andreas iOS ARM64
// Scripts, metodologia, mapeamentos e conclusões organizados por BN_JK.
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import java.io.*;
import java.util.*;

public class FindPositionHeadingSetters extends BN_JKScript {

    static class Score {
        Function f;
        int matrixPos;
        int simplePos;
        int heading;
        boolean matrixPtr;
        boolean sincos;

        Score(Function f) {
            this.f = f;
        }

        int total() {
            return matrixPos * 4 +
                   simplePos * 3 +
                   heading * 2 +
                   (matrixPtr ? 3 : 0) +
                   (sincos ? 3 : 0);
        }
    }

    boolean isStore(String s) {
        s = s.toLowerCase();
        return s.startsWith("str ") ||
               s.startsWith("stp ");
    }

    public void run() throws Exception {

        PrintWriter out = new PrintWriter(
            "/root/BN_JK-analysis/output/position_heading_candidates.txt"
        );

        FunctionManager fm = currentProgram.getFunctionManager();
        Listing listing = currentProgram.getListing();

        ArrayList<Score> results = new ArrayList<>();

        FunctionIterator fit = fm.getFunctions(true);

        while (fit.hasNext()) {

            Function f = fit.next();
            Score sc = new Score(f);

            InstructionIterator ii =
                listing.getInstructions(f.getBody(), true);

            while (ii.hasNext()) {

                Instruction ins = ii.next();
                String s = ins.toString().toLowerCase();

                // entity->matrix
                if (s.contains("#0x18]"))
                    sc.matrixPtr = true;

                // writes into CMatrix translation
                if (isStore(s)) {
                    if (s.contains("#0x30]"))
                        sc.matrixPos++;

                    if (s.contains("#0x34]"))
                        sc.matrixPos++;

                    if (s.contains("#0x38]"))
                        sc.matrixPos++;

                    // simple placement candidates
                    if (s.contains("#0x8]"))
                        sc.simplePos++;

                    if (s.contains("#0xc]"))
                        sc.simplePos++;

                    if (s.contains("#0x10]"))
                        sc.simplePos++;

                    if (s.contains("#0x14]"))
                        sc.heading++;
                }

                // ARM64 import address for ___sincosf_stret
                if (s.contains("0x10043de14"))
                    sc.sincos = true;
            }

            if ((sc.matrixPos >= 2 && sc.matrixPtr) ||
                sc.simplePos >= 3 ||
                (sc.heading > 0 && sc.sincos)) {

                results.add(sc);
            }
        }

        Collections.sort(results,
            new Comparator<Score>() {
                public int compare(Score a, Score b) {
                    return Integer.compare(
                        b.total(),
                        a.total()
                    );
                }
            }
        );

        out.println("=== POSITION / HEADING CANDIDATES ===");

        int n = 0;

        for (Score sc : results) {

            if (n++ >= 120)
                break;

            out.println();
            out.println(
                "FUNCTION=" +
                sc.f.getEntryPoint() +
                "|" +
                sc.f.getName()
            );

            out.println(
                "SCORE=" + sc.total() +
                " MATRIX_POS=" + sc.matrixPos +
                " SIMPLE_POS=" + sc.simplePos +
                " HEADING=" + sc.heading +
                " MATRIX_PTR=" + sc.matrixPtr +
                " SINCOS=" + sc.sincos
            );

            InstructionIterator ii =
                listing.getInstructions(
                    sc.f.getBody(),
                    true
                );

            while (ii.hasNext()) {

                Instruction ins = ii.next();
                String s = ins.toString().toLowerCase();

                if (s.contains("#0x18]") ||
                    s.contains("#0x30]") ||
                    s.contains("#0x34]") ||
                    s.contains("#0x38]") ||
                    s.contains("#0x8]") ||
                    s.contains("#0xc]") ||
                    s.contains("#0x10]") ||
                    s.contains("#0x14]") ||
                    s.contains("0x10043de14")) {

                    out.println(
                        "  " +
                        ins.getAddress() +
                        " | " +
                        ins
                    );
                }
            }

            out.println("CALLERS:");

            int c = 0;

            for (Function caller :
                    sc.f.getCallingFunctions(monitor)) {

                out.println(
                    "  " +
                    caller.getEntryPoint() +
                    "|" +
                    caller.getName()
                );

                if (++c >= 20)
                    break;
            }
        }

        out.close();

        println("POSITION_HEADING_SCAN_COMPLETE");
    }
}
