import sys

def main(FILE,BYTE):
    '''
    Questa funzione produce un file ben formattato da fornire in input ad hidder per nascondere informazioni dentro le code caves.
    Prende in input:
        1) l'output del programma CaveFinder come una tupla di stringhe;
        2) il numero di byte da voler nascondere dentro le code caves.
    '''
    i=0     # Indice della riga all'interno di FILE
    ac=0    # Accumulatore di byte delle code caves: quando ac>=BYTE non cerco altre code caves
    LUNGHEZZA=len(FILE)
    output=list()
    
    try:
        while i<LUNGHEZZA:
            if "Cave begin" in FILE[i]:
                inizio=int(FILE[i].split()[-1],0)      # Mi prendo l'indirizzo di inizio della code cave
                                                       # il parametro 0 mi permette di convertire in base 10
                                                       # senza preoccuparmi della base di partenza
                output.append(str(inizio))
                i+=1                
                # Vado alla ricerca della dimensione della code cave
                while i < LUNGHEZZA:
                    if "Cave end" in FILE[i]: # Controllo se ho trovato l'indirizzo di fine della code cave
                        fine=int(FILE[i].split()[-1],0)
                        if ac+(fine-inizio)>=BYTE:
                            assert (fine-inizio)>=(BYTE-ac)
                            output.append(str(BYTE-ac))     # Quello che serve per arrivare a BYTE
                            #ac=BYTE    # A questo punto non serve piu` conteggiare
                            i=LUNGHEZZA-1 # Cosi` interrompo il while esterno (-1 perche' poi aggiungo alla fine di questo while)
                        else:
                            ac+=fine-inizio
                            output.append(str(fine-inizio))
                        break   # Dimensione code cave trovata
                    if "Cave size" in FILE[i]:   # Controllo se ho trovato la dimensione della code cave bella pronta
                        if ac+(int(FILE[i].split()[-2],0))>=BYTE:
                            assert int(FILE[i].split()[-2],0) >= BYTE-ac
                            output.append(str(BYTE-ac))
                            #ac=BYTE    # A questo punto non serve piu` conteggiare
                            i=LUNGHEZZA-1 # Cosi` interrompo il while esterno (-1 perche' poi aggiungo alla fine di questo while)
                        else:
                            ac+=int(FILE[i].split()[-2],0)
                            output.append(str(int(FILE[i].split()[-2],0)))
                        break   # Dimensione code cave trovata
                    i+=1
            i+=1
    except Exception:
        print("Errore: il file fornito come risultato di CaveFinder ha qualcosa che non va")
    
    print(output)
    return

if "__main__"==__name__:
    try:
        BYTE=int(sys.argv[1])
        if BYTE<1:
            raise ValueError
        if len(sys.argv)>2:
            # E` stato fornito il file contenente l'output di CaveFinder
            with open(sys.argv[2],'r',encoding="UTF-8") as f:
                FILE=f.readlines()
        else:
            # L'output di CaveFinder viene fornito da standard input: da pipe oppure con redirezione <
            FILE=sys.stdin.readlines()
        FILE=tuple(FILE)
        main(FILE,BYTE)
    except ValueError:
        print("Errore: Il parametro che indica il numero di byte da nascondere nelle code caves non e` un numero naturale maggiore di zero")
    except IndexError:
        print("Errore: Non e` stato fornito il numero di byte da nascondere nelle code caves")
