import sys

def main(FILE,BYTE):
    '''
    Questa funzione produce un file ben formattato da fornire in input ad hidder per nascondere informazioni dentro le code caves.
    Prende in input:
        1) l'output del programma CaveFinder come una tupla di stringhe;
        2) il numero di byte da voler nascondere dentro le code caves.
    '''
    INT_BYTES_LEN=4 # Il numero di byte che vengono utilizzati in hidder per rappresentare un intero
    MAX_INT=2**((INT_BYTES_LEN*8)-1)-1 # Il massimo numero intero rappresentabile con i byte di cui sopra
    
    i=0     # Indice della riga all'interno di FILE
    ac=0    # Accumulatore di byte delle code caves: quando ac>=BYTE non cerco altre code caves
    LUNGHEZZA=len(FILE)
    output=list()
    accoppiati=False    # Indica se ad una code cave e` stata correttamente trovata la dimensione
    try:
        while i<LUNGHEZZA:
            if "Cave begin" in FILE[i]:
                inizio=int(FILE[i].split()[-1],0)      # Mi prendo l'indirizzo di inizio della code cave
                                                       # il parametro 0 mi permette di convertire in base 10
                                                       # senza preoccuparmi della base di partenza
                if inizio<0 or inizio>MAX_INT:
                    raise Exception
                output.append(inizio)
                i+=1
                accoppiati=False
                # Vado alla ricerca della dimensione della code cave
                while i < LUNGHEZZA:
                    if "Cave end" in FILE[i]: # Controllo se ho trovato l'indirizzo di fine della code cave
                        fine=int(FILE[i].split()[-1],0)
                        if fine<0 or fine>MAX_INT:
                            raise Exception
                        dimensioneCC=fine-inizio
                        if ac+dimensioneCC>=BYTE:
                            assert dimensioneCC>=(BYTE-ac)
                            output.append(BYTE-ac)     # Quello che serve per arrivare a BYTE
                            ac=BYTE
                            i=LUNGHEZZA-1 # Cosi` interrompo il while esterno (-1 perche' poi aggiungo alla fine di questo while)
                        else:
                            ac+=dimensioneCC
                            output.append(dimensioneCC)
                        accoppiati=True
                        break   # Dimensione code cave trovata
                    if "Cave size" in FILE[i]:   # Controllo se ho trovato la dimensione della code cave bella pronta
                        dimensioneCC=int(FILE[i].split()[-2],0)
                        if dimensioneCC<0 or dimensioneCC>MAX_INT:
                            raise Exception
                        if ac+dimensioneCC>=BYTE:
                            assert dimensioneCC >= BYTE-ac
                            output.append(BYTE-ac)
                            ac=BYTE
                            i=LUNGHEZZA-1 # Cosi` interrompo il while esterno (-1 perche' poi aggiungo alla fine di questo while)
                        else:
                            ac+=dimensioneCC
                            output.append(dimensioneCC)
                        accoppiati=True
                        break   # Dimensione code cave trovata
                    i+=1
            i+=1
        else:   # Se finisco di analizzare il file senza errori
            if False==accoppiati:
                raise Exception
    except Exception:
        print("Errore: Il file fornito come risultato di CaveFinder ha qualcosa che non va")
    else:   # Se non ho riscontrato eccezioni
        print("Sono stati trovati",ac,"byte di code caves su",BYTE,"richiesti\n")
        print("Verra` scritto su output_setaccio.bin:\n",
              "1) l'intero che indica la lunghezza della lista di interi;\n",
              "2) la seguente lista di interi:\n",output,sep="")
        try:
            with open("output_setaccio.bin","bw") as f:
                if(len(output)>MAX_INT):
                    raise OverflowError
                else:
                    f.write( len(output).to_bytes(INT_BYTES_LEN,byteorder="little") )
                for intero in output:
                    f.write( intero.to_bytes(INT_BYTES_LEN,byteorder="little") ) # Scrivo l'intero in INT_BYTES_LEN byte con codifica little-endian
        except OverflowError: # 4 byte non bastano per rappresentare l'intero (quando scandisco il file ho gia` controllato, rimane da controllare la lunghezza della variabile ``output")
            print('Errore: Non e` possibile rappresentare con 4 byte uno dei numeri forniti oppure non e` possibile rappresentare (con 4 byte) la lunghezza della lista di interi.\nModificare il codice sorgente di questo programma e di hidder.h di conseguenza.')
        except EnvironmentError: # parent of IOError, OSError *and* WindowsError where available
            print("Errore: Non e` stato possibile scrivere sul file")
    
    return

if "__main__"==__name__:
    try:
        BYTE=int(sys.argv[1])
        if BYTE<1:
            raise ValueError
        if len(sys.argv)>2:
            # E` stato fornito il file contenente l'output di CaveFinder
            with open(sys.argv[2],"r",encoding="UTF-8") as f:
                FILE=f.readlines()
        else:
            # L'output di CaveFinder viene fornito da standard input: da pipe oppure con redirezione <
            FILE=sys.stdin.readlines()
        FILE=tuple(FILE)
    except ValueError:
        print("Errore: Il parametro che indica il numero di byte da nascondere nelle code caves non e` un numero naturale maggiore di zero")
        print(
                "Uso:\n",
                "python3 setaccio.py N output_CaveFinder.txt\n",
                "oppure\n",
                "python3 setaccio.py N < output_CaveFinder.txt\n",
                "oppure\n",
                "cavefinder --size N1 file_eseguibile | python3 setaccio.py N2"
             ,sep='\t')
    except IndexError:
        print("Errore: Non e` stato fornito il numero di byte da nascondere nelle code caves")
        print(
                "Uso:\n",
                "python3 setaccio.py N output_CaveFinder.txt\n",
                "oppure\n",
                "python3 setaccio.py N < output_CaveFinder.txt\n",
                "oppure\n",
                "cavefinder --size N1 file_eseguibile | python3 setaccio.py N2"
             ,sep='\t')
    except Exception:
        print("Errore imprevisto")
        print(
                "Uso:\n",
                "python3 setaccio.py N output_CaveFinder.txt\n",
                "oppure\n",
                "python3 setaccio.py N < output_CaveFinder.txt\n",
                "oppure\n",
                "cavefinder --size N1 file_eseguibile | python3 setaccio.py N2"
             ,sep='\t')
    else:   # Se tutto e` andato liscio, chiamo main
        main(FILE,BYTE)
        
