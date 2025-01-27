from automata.fa.Moore import Moore
import string
import sys, os

from myerror import MyError

error_handler = MyError('LexerErrors')

global check_cm
global check_key

letras = string.ascii_letters # 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
digitos = string.digits # '0123456789'
chars_para_id = letras + digitos + '_' # conjunto para ID

moore = Moore(
    states=['q0', 'q1', 'q2', 'q3', 'q4','q5','q6','q7','q8','q9','q10','q11','q12','q13','q14','q15','q16','q17','q18','q19','q20','q21','q22','q23',
    'q24','q25','q26','q27','q28','q29','q30','q31','q32','q33','q34','q35','q36','q37','q38','q39','q40','q41','q42','q43','q44','q45','q46','q47','q48',
    'q49','q50','q51','q52','q53','q54','q55','q56','q57','q58','q59','q60','q61','q62','q63','q64','q65','qID'],

    input_alphabet=list(chars_para_id) + ['+', '-', '*', '/', '<', '>', '=', '(', ')', '[', ']', '{', '}', ';', ',', '\n', ' ',], 

    # input_alphabet=['' ,'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','0','1','2',
    # '3','4','5','6','7','8','9','\n','+','-','*','/','<','>','=','(',')','[',']','{','}',';',','],

    output_alphabet=['INT', 'ELSE','IF','WHILE','FLOAT','RETURN','VOID','MINUS','PLUS','TIMES','DIVIDE','DIFFERENT','LPAREN','RPAREN','NUMBER','ID',
    'LBRACKETS','RBRACKETS','COMMA','LBRACES','RBRACES','GREATER','GREATER_EQUAL','LESS','LESS_EQUAL','EQUALS','SEMICOLON','ATTRIBUTION'],

    transitions={
                  'q0' : {
                      'i' : 'q1',
                  },
                  'q1': {
                      'f': 'q13','n': 'q10',
                  },
                  'q10': {
                      't': 'q11',

                  },
                  'q11': {
                    '':'q12', '\n': 'q12',
                  },
                  'q13' : {
                        '':'q14', '\n': 'q14',
                  },
              },

    initial_state='q0',
    output_table={
                  'q0' : '',
                  'q1' : '',
                  'q10' : '',
                  'q11' : '',
                  'q12' : 'INT',
                  'q14' : 'IF',
              }
              )


def main():
    check_cm = False
    check_key = False
    
    for idx, arg in enumerate(sys.argv):
        # print("Argument #{} is {}".format(idx, arg))
        aux = arg.split('.')
        if aux[-1] == 'cm':
            check_cm = True
            idx_cm = idx

        if(arg == "-k"):
            check_key = True
    
    # print ("No. of arguments passed is ", len(sys.argv))

    if(len(sys.argv) < 3):
        raise TypeError(error_handler.newError(check_key, 'ERR-LEX-USE'))

    if not check_cm:
      raise IOError(error_handler.newError(check_key, 'ERR-LEX-NOT-CM'))
    elif not os.path.exists(sys.argv[idx_cm]):
        raise IOError(error_handler.newError(check_key, 'ERR-LEX-FILE-NOT-EXISTS'))
    else:
        data = open(sys.argv[idx_cm])
        source_file = data.read()

        if not check_cm:
            print("Definição da Máquina")
            print(moore)
            print("Entrada:")
            print(source_file)
            print("Lista de Tokens:")
        
        print(moore.get_output_from_string(source_file))


if __name__ == "__main__":

    try:
        main()
    except Exception as e:
        print(e)
    except (ValueError, TypeError):
        print(e)