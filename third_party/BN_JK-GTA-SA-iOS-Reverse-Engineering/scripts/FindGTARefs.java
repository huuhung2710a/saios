//@category BN_JK


// BN_JK Reverse Engineering Research
// Autor e responsável pelo estudo: BN_JK
// Projeto: GTA San Andreas iOS ARM64
// Scripts, metodologia, mapeamentos e conclusões organizados por BN_JK.
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;

import java.io.*;
import java.util.*;

public class FindGTARefs extends BN_JKScript {

    private final String[] terms = {
        "CPlayerPed",
        "CPed",
        "CVehicle",
        "CObject",
        "CEntity",
        "CWorld",
        "CStreaming",
        "CTask",
        "CGame",
        "PlayerPed",
        "VehicleModelInfo"
    };

    @Override
    public void run() throws Exception {

        File output =
            new File("/root/BN_JK-analysis/output/gta_xrefs.txt");

        PrintWriter out =
            new PrintWriter(new BufferedWriter(new FileWriter(output)));

        Listing listing = currentProgram.getListing();
        ReferenceManager refs = currentProgram.getReferenceManager();
        FunctionManager fm = currentProgram.getFunctionManager();

        DataIterator data = listing.getDefinedData(true);

        while (data.hasNext()) {

            Data d = data.next();

            if (!d.hasStringValue())
                continue;

            Object value = d.getValue();

            if (value == null)
                continue;

            String text = value.toString();

            boolean match = false;

            for (String term : terms) {
                if (text.toLowerCase().contains(term.toLowerCase())) {
                    match = true;
                    break;
                }
            }

            if (!match)
                continue;

            Address stringAddress = d.getAddress();

            out.println();
            out.println("==================================================");
            out.println("STRING: " + text);
            out.println("STRING_ADDR: " + stringAddress);

            ReferenceIterator iterator =
                refs.getReferencesTo(stringAddress);

            int count = 0;

            while (iterator.hasNext()) {

                Reference ref = iterator.next();
                Address from = ref.getFromAddress();

                Function function =
                    fm.getFunctionContaining(from);

                out.println("XREF: " + from);

                if (function != null) {

                    out.println(
                        "FUNCTION: " +
                        function.getEntryPoint() +
                        " | " +
                        function.getName()
                    );

                    Set<Function> callers =
                        function.getCallingFunctions(monitor);

                    for (Function caller : callers) {

                        out.println(
                            "  CALLER: " +
                            caller.getEntryPoint() +
                            " | " +
                            caller.getName()
                        );
                    }

                    Set<Function> callees =
                        function.getCalledFunctions(monitor);

                    for (Function callee : callees) {

                        out.println(
                            "  CALLEE: " +
                            callee.getEntryPoint() +
                            " | " +
                            callee.getName()
                        );
                    }
                }

                count++;
            }

            out.println("XREF_COUNT: " + count);
        }

        out.close();

        println("ZONAAPPLE_XREF_EXPORT_COMPLETE");
    }
}
