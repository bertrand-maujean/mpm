#!/usr/bin/python3.5

import sys
from Crypto.Cipher import AES

messages = []
cible = "" # c ou h selon qu'on veut les constantes à linker ou les includes 


# ------------------------------
# Identification des codes de langue existants
# attribution des valeurs
# Return : tableau des codes
def cherche_lang(messages):
    ensemble_codes_lang = set(); 
    for m in messages:
        for l in m["msg"]:
            ensemble_codes_lang.add(l["lang"]);

    result = []
    for c in ensemble_codes_lang:
        result.append(c)
        
    result.sort()
      
    return result



# -------------------------------
# Identification des id de messages existants
# Attribution des valeurs d'id
# Return : tableau des id
def cherche_id(messages):
    ensemble_id = set();
    for m in messages:
        ensemble_id.add(m["id"]);

    result = []
    for c in ensemble_id:
        result.append(c);

    result.sort()       
    return result



# ---------------------------------
# Exporte les constantes d'id de message
def exporte_ids(ids):
    if cible=="c":
        return
    
    print("\n\n// Définition des ids de message\n", end="")
    print("#define MSG_NB_ID "+str(len(ids))+"\n")
    for i in range(0, len(ids)):
        print("#define "+ids[i]+" "+str(i))
    print("\n\n", end="")       
    return


# ---------------------------------
# Exporte les constantes de code langue
def exporte_codes_lang(langs):
    print("\n\n// Définition des codes de langue\n", end="")
    if cible=="h":
        print("#define MSG_NB_LANG "+str(len(langs)))
        print("extern const char *msg_codes_lang[];")
        
    else:    
        print("const char *msg_codes_lang[] = { ");
        for i in range (0, len(langs)):
            print(" \""+ langs[i] + "\" ", end="")
            if (i<len(langs)-1):
                print(",", end="")
            else:
                print(" };\n", end="")

    return


# -------------------------------------
# Création des tableaux de donnée et index
# return :
# - data : tableau de bytes avec les messages
# - index : tableau de uint32 avec les index des messages dans le tableau précedent
# Note : index contient -1 pour une chaine inexistante (= il faudra prendre une langue par défaut)
def genere_tableaux(messages, langs, ids):
    data = b"" # tableau de bytes vide
    index = [] # tableau d'index entier vide

    # initialise à -1 tous les index
    # par défaut, on a pas de chaine
    for i in range (0, len(langs)*len(ids)):
        index.append(-1)
        

    for m in messages:
        # recherche l'index de l'id de message
        index_msg = ids.index(m["id"])
        
        for l in m["msg"]:
            # recherche l'index du code lang
            index_lang = langs.index(l["lang"])

            # injecte l'index de la nouvelle chaine
            index[index_msg* len(langs) + index_lang ] = len(data)
            
            # injecte la chaine dans les data
            data = data + l["msg"].encode('utf8')
            data = data + b"\0"

    return (data, index)


# -----------------------------------------------
# exporte les constantes data et index
def exporte_data_index(data, index):
    while (len(data) & 0xf) != 0:
        data = data + b"\0"

    
    if cible=="h":
        print("extern const unsigned char msg_data[];")
        print("extern const int32_t msg_index[];")
        print("#define MSG_DATA_LEN "+str(len(data)))
        
    else: 
        #chiffreur = AES.new(b"0123456789abcdef0123456789abcdef", mode=AES.MODE_CBC, IV="0123456789abcdef")
        #data_chiffree = chiffreur.encrypt(data)
        data_chiffree = data
	
        print("// Bloc des messages agrégés")
        print("unsigned char msg_data[] = { ")
        for i in range(0, len(data)):
            print(data_chiffree[i], end="")
            if i< len(data)-1:
                print(",", end="")
                if (i % 20) == 19:
                    print("")
            else:
                print(" };\n")

        print("// index de recherche dans le bloc data")
        print("const int32_t msg_index[] = { ")
        for i in range(0, len(index)):
            print(index[i], end="")
            if i<len(index)-1:
                print(",", end="")
                if (i % 20) == 19:
                    print("")

            else:
                print(" }; ")
                
    return


# ------------------------------------------------
# Programme principal
def main():
    global cible
    if len(sys.argv) != 3:
        print("compile_messages.py <h|c> <source.inc>")
        exit()
        
    print("#include <stdint.h>")

    if sys.argv[1] == "c":
        cible = "c"
        print("int msg_current_lang = 0;\n")
        print("int msg_default_lang = 0;\n")



        
    elif sys.argv[1] == "h":
        cible = "h"
        print("#ifdef __cplusplus\nextern \"C\" {\n#endif")
        print("extern int msg_current_lang;")
        print("extern int msg_default_lang;")
        print("char *msg_get_string(int id);")
        print("#define _MSG(id) (&msg_data[msg_index[MSG_NB_LANG*id + msg_current_lang]])") 
        
    else:
        print("compile_messages.py <h|c> <source.inc>")
        exit()       

    messages=eval(open(sys.argv[2]).read()) 
    
    langs = cherche_lang(messages)
    exporte_codes_lang(langs)

    ids = cherche_id(messages)
    exporte_ids(ids)

    (data, index) = genere_tableaux(messages, langs, ids)

    exporte_data_index(data, index)

    if cible=="c":
        print("#define MSG_NB_LANG "+str(len(langs)))
        print("\n\nchar *msg_get_string(int id) {\n"
              "   int i=msg_index[MSG_NB_LANG*id + msg_current_lang];\n"
              "   if (i==-1) i = msg_index[MSG_NB_LANG*id + msg_default_lang]; \n"
              "   return (char*) &msg_data[i]; \n"
              "}")
    else:
        print("#ifdef __cplusplus\n}\n#endif")







    return


# ---------------------------------------------------

if __name__ == "__main__":
    main()
    
	





