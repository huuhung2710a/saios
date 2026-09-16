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

public class ExportZonaApple extends BN_JKScript {

    @Override
    public void run() throws Exception {

        File outDir = new File("/root/BN_JK-analysis/output");
        outDir.mkdirs();

        exportFunctions(new File(outDir, "functions.txt"));
        exportSymbols(new File(outDir, "symbols.txt"));
        exportStrings(new File(outDir, "strings.txt"));

        println("ZONAAPPLE_EXPORT_COMPLETE");
    }

    private void exportFunctions(File file) throws Exception {

        PrintWriter out = new PrintWriter(
            new BufferedWriter(new FileWriter(file))
        );

        FunctionManager fm = currentProgram.getFunctionManager();

        FunctionIterator funcs = fm.getFunctions(true);

        while (funcs.hasNext()) {

            Function f = funcs.next();

            out.println(
                f.getEntryPoint() + "|" +
                f.getName() + "|" +
                f.getBody().getNumAddresses()
            );
        }

        out.close();
    }

    private void exportSymbols(File file) throws Exception {

        PrintWriter out = new PrintWriter(
            new BufferedWriter(new FileWriter(file))
        );

        SymbolTable table = currentProgram.getSymbolTable();

        SymbolIterator it = table.getAllSymbols(true);

        while (it.hasNext()) {

            Symbol s = it.next();

            out.println(
                s.getAddress() + "|" +
                s.getName() + "|" +
                s.getSymbolType()
            );
        }

        out.close();
    }

    private void exportStrings(File file) throws Exception {

        PrintWriter out = new PrintWriter(
            new BufferedWriter(new FileWriter(file))
        );

        Listing listing = currentProgram.getListing();

        DataIterator data = listing.getDefinedData(true);

        while (data.hasNext()) {

            Data d = data.next();

            if (d.hasStringValue()) {

                Object value = d.getValue();

                if (value != null) {

                    String text = value.toString()
                        .replace("\n", "\\n")
                        .replace("\r", "\\r");

                    out.println(
                        d.getAddress() + "|" + text
                    );
                }
            }
        }

        out.close();
    }
}
