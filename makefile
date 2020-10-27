# capstone library name (without prefix 'lib' and suffix '.so')
# -Wall attiva tutti i warning
# preso un target:dipendenze -> %@ indica il target, %< la prima dipendenza, %^ tutte le dipendenze
LIB_CAPSTONE := -lcapstone 
LIB_HIDDER := -lhidder
LIB_KEYSTONE_LDFLAGS := -lkeystone -lstdc++ -lm
LIB_CRYPTO := -lssl -lcrypto
CC := gcc 

LIB_AES := ./tiny-

HEADER := ./header
PATH_LIB_HIDDER := ./lib
HIDDER_LIB_NAME := libhidder.so

OBJ_DIR := ./obj
SRC_DIR := ./src
# wildcard viene sostituito con tutti i file che matchano le regex successive separate da una virgola 
# ovvero in questo caso tutti i   .c in SRC_DIR
SRC_FILES := $(wildcard $(SRC_DIR)/*.c)
# patsubst pattern, replacement, text  := questo comando sostituice da TEXT tutti i match di PATTERN 
# con REPLACEMENT, ovvero in questo caso sostituisce tutti i path ./src/***.c con ./obj/***.o.
# questi 2 comandi sono usati per compilare in automatico tutti i .c in src e mettere in obj il .o
OBJ_FILES := $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(SRC_FILES))

#
start: clean makedir main
	
makedir:
	@cd ..
	@mkdir -p $(OBJ_DIR)
	@mkdir -p $(PATH_LIB_HIDDER)

# questo comando linka il main.o con le librerie e crea l'eseguibile main.exe
main : $(OBJ_FILES)
	${CC}  -Wall -O3 -g  $(OBJ_FILES) -I$(HEADER) $(LIB_CAPSTONE) $(LIB_CRYPTO) ${LIB_KEYSTONE_LDFLAGS} -o hidder
	${CC}  -Wall -O3 -g  $(OBJ_FILES) -I$(HEADER) $(LIB_CAPSTONE) $(LIB_CRYPTO) ${LIB_KEYSTONE_LDFLAGS} -o decoder
#-fsanitize=address,undefined   #per controllare i problemi dell'heap

# il comando interno (-c) compila un .c in un .o non eseguibile ( un file oggetto "binario" )
# %.o è come una regex, indica che il target viene chiamato da ogni *.o es main.o/compare.o...
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	${CC} -c $< -o $@ -I$(HEADER)

clean:
	@rm -rf $(OBJ_DIR) $(PATH_LIB_HIDDER)
	@rm -f main *.o $(HIDDER_LIB_NAME)

	