/*
*   header contenenti le istruzioni, struct e costanti/variabili globali
*   utili per l'embending.
*/
#include "hidder.h"

int main(int argc, char *argv[]){
    int ret;
    
    if (strstr (argv[0], "decoder"))  ret=decoder_main (argc, argv);
    else if (strstr (argv[0], "hidder"))  ret=hidder_main  (argc, argv);
    else fprintf (stderr, "use 'hidder' or 'decoder'\n");

    return ret;
}
