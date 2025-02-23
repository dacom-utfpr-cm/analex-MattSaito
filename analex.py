from automata.fa.Moore import Moore
import string
import sys, os
from myerror import MyError
error_handler = MyError('LexerErrors')

global check_cm
global check_key

moore = Moore(
    states=['q0', 'q1', 'q2', 'q3', 'q4', 'q5', 'q6', 'q7', 'q8', 'q9', 'q10', 'q11', 'q12', 'q13', 'q14', 'q15', 'q16', 'q17', 'q18', 'q19', 'q20', 'q21', 'q22', 'q23',
            'q24', 'q25', 'q26', 'q27', 'q28', 'q29', 'q30', 'q31', 'q32', 'q33', 'q34', 'q35', 'q36', 'q37', 'q38', 'q39', 'q40', 'q41', 'q42', 'q43', 'q44', 'q45', 'q46', 'q47', 'q48',
            'q49', 'q50', 'q51', 'q52', 'q53', 'q54', 'q55', 'q56', 'q57', 'q58', 'q59', 'q60', 'q61', 'q62', 'q63', 'q64', 'q65', 'qID_START', 'qID_CONT', 'qNUM_START', 'qNUM_CONT','qCOMS','qCOMB','qCOME'],

    input_alphabet=list(string.ascii_letters) + list(string.digits) + ['+','!', '-', '*', '/', '<', '>', '=', '(', ')', '[', ']', '{', '}', ';', ',', '\n', ' '],

    output_alphabet=['INT', 'ELSE', 'IF', 'WHILE', 'FLOAT', 'RETURN', 'VOID', 'MINUS', 'PLUS', 'TIMES', 'DIVIDE', 'DIFFERENT', 'LPAREN', 'RPAREN', 'NUMBER', 'ID',
                     'LBRACKETS', 'RBRACKETS', 'COMMA', 'LBRACES', 'RBRACES', 'GREATER', 'GREATER_EQUAL', 'LESS', 'LESS_EQUAL', 'EQUALS', 'SEMICOLON', 'ATTRIBUTION'],

    transitions={
        'q0': {
            'w': 'q2', 'i': 'q1', 'e': 'q18', 'f': 'q23', 'r': 'q29', 'v': 'q36', '-': 'q41', '+': 'q3', '*': 'q42', '/': 'q43',
            '!': 'q52', '(': 'q55', ')': 'q56', '[': 'q57', ']': 'q58', '{': 'q59', '}': 'q60', '<': 'q4', '>': 'q44', '=': 'q49',
            ';': 'q61', ',': 'q62', ' ': 'q0', '\n': 'q0',

            **{c: 'qID_START' for c in string.ascii_letters if c not in {'w', 'i', 'e', 'f', 'r', 'v'}},  
            **{c: 'qNUM_START' for c in string.digits}
        },

        'qID_START': {
            **{c: 'qID_CONT' for c in string.ascii_letters + string.digits},  # Começa um ID
            **{c: 'q0' for c in [' ', '\n', '+', '-', '*', '/', '<', '>', '=', '(', ')', '[', ']', '{', '}', ';', ',']}  # Termina o ID
        },

        'qID_CONT': {
            **{c: 'qID_CONT' for c in string.ascii_letters + string.digits},  # Continua como ID
            **{c: 'q0' for c in [' ', '\n', '+', '-', '*', '/', '<', '>', '=', '(', ')', '[', ']', '{', '}', ';', ',']}  # Termina o ID
        },
        
        'qCOMS': {c: 'qCOMB' for c in string.printable},  # Consome caracteres dentro do comentário
        'qCOMB': {'*': 'qCOME', **{c: 'qCOMB' for c in string.printable if c not in ["*"]}},  # Aguarda "*/"
        'qCOME': {'/': 'q0', **{c: 'qCOMB' for c in string.printable if c not in "/"}},  # Fecha comentário

        'qNUM_START': {c: 'qNUM_CONT' for c in string.digits},  # Começa a ler número
        'qNUM_CONT': {c: 'qNUM_CONT' for c in string.digits},  # Continua lendo número
        'qNUM_CONT': {c: 'q0' for c in [' ', '\n', '+', '-', '*', '/', '<', '>', '=', '(', ')', '[', ']', '{', '}', ';', ',']},  # Número termina

        'q1': {**{c: 'qID_CONT' for c in string.ascii_letters if c not in ['n','f']},' ' : 'qID_CONT', 'n': 'q10', 'f': 'q13'},
        'q2': {**{c: 'qID_CONT' for c in string.ascii_letters if c != 'h'},' ' : 'qID_CONT','h': 'q5'},
        'q3': {' ': 'q0'},
        'q4': {'=': 'q16', ' ': 'q15'},
        'q5': {**{c: 'qID_CONT' for c in string.ascii_letters if c != 'i'},'i': 'q6'},
        'q6': {**{c: 'qID_CONT' for c in string.ascii_letters if c != 'l'},'l': 'q7'},
        'q7': {**{c: 'qID_CONT' for c in string.ascii_letters if c != 'e'},'e': 'q8'},
        'q8': {' ': 'q9'},
        'q9': {'\n': 'q0'},
        'q10': {**{c: 'qID_CONT' for c in string.ascii_letters if c != 't'},'t': 'q11'},
        'q11': {' ': 'q12'},
        'q12': {'\n': 'q0'},
        'q13': {' ': 'q14'},
        'q14': {'\n': 'q0'},
        'q15': {'\n': 'q0'},
        'q16': {' ': 'q0'},
        'q18': {**{c: 'qID_CONT' for c in string.ascii_letters if c != 'l'},' ': 'qID_CONT','l': 'q19'},
        'q19': {**{c: 'qID_CONT' for c in string.ascii_letters if c != 's'},'s': 'q20'},
        'q20': {**{c: 'qID_CONT' for c in string.ascii_letters if c != 'e'},'e': 'q21'},
        'q21': {' ': 'q22'},
        'q22': {'\n': 'q0'},
        'q23': {**{c: 'qID_CONT' for c in string.ascii_letters if c != 'l'},' ' : 'qID_CONT','l': 'q24'},
        'q24': {**{c: 'qID_CONT' for c in string.ascii_letters if c != 'o'},'o': 'q25'},
        'q25': {**{c: 'qID_CONT' for c in string.ascii_letters if c != 'a'},'a': 'q26'},
        'q26': {**{c: 'qID_CONT' for c in string.ascii_letters if c != 't'},'t': 'q27'},
        'q27': {' ': 'q28'},
        'q28': {'\n': 'q0'},
        'q29': {**{c: 'qID_CONT' for c in string.ascii_letters if c != 'e'},' ' : 'qID_CONT', 'e': 'q30'},
        'q30': {**{c: 'qID_CONT' for c in string.ascii_letters if c != 't'},'t': 'q31'},
        'q31': {**{c: 'qID_CONT' for c in string.ascii_letters if c != 'u'},'u': 'q32'},
        'q32': {**{c: 'qID_CONT' for c in string.ascii_letters if c != 'r'},'r': 'q33'},
        'q33': {**{c: 'qID_CONT' for c in string.ascii_letters if c != 'n'},'n': 'q34'},
        'q34': {' ': 'q35'},
        'q35': {'\n': 'q0'},
        'q36': {**{c: 'qID_CONT' for c in string.ascii_letters if c != 'o'},' ' : 'qID_CONT','o': 'q37'},
        'q37': {**{c: 'qID_CONT' for c in string.ascii_letters if c != 'i'},'i': 'q38'},
        'q38': {**{c: 'qID_CONT' for c in string.ascii_letters if c != 'd'},'d': 'q39'},
        'q39': {' ': 'q40'},
        'q40': {'\n': 'q0'},
        'q41' : {' ': 'q0'},
        'q42' : {' ': 'q0'},
        'q43' : {'*': 'qCOMS',' ': 'q0'},
        'q44' : {'=' : 'q46', ' ' : 'q45'},
        'q45' : {'\n': 'q0'},
        'q46' : {' ' : 'q0'},
        'q48' : {' ': 'q0'},
        'q49' : {'=' : 'q48', ' ' : 'q50'},
        'q50' : {'\n': 'q0'},
        'q52' : {'=' : 'q53'},
        'q53' : {' ': 'q0'},
        'q55' : {' ': 'q0'},
        'q56' : {' ': 'q0'},
        'q57' : {' ': 'q0'},
        'q58' : {' ': 'q0'},
        'q59' : {' ': 'q0'},
        'q60' : {' ': 'q0'},
        'q61' : {' ': 'q0'},
        'q62' : {' ': 'q0'},

    },
    initial_state='q0',
    output_table={
        'q0': '',
        'q1': '',
        'q2': '',
        'q3': 'PLUS',
        'q4': '',
        'q5': '',
        'q6': '',
        'q7': '',
        'q8': 'WHILE',
        'q9': 'WHILE',
        'q10': '',
        'q11': 'INT',
        'q12': 'INT',
        'q13': '',
        'q14': 'IF',
        'q15': 'LESS',
        'q16': 'LESS_EQUAL',
        'q18': '',
        'q19': '',
        'q20': '',
        'q21': 'ELSE',
        'q22': 'ELSE',
        'q23': '',
        'q24': '',
        'q25': '',
        'q26': '',
        'q27': 'FLOAT',
        'q28': 'FLOAT',
        'q29': '',
        'q30': '',
        'q31': '',
        'q32': '',
        'q33': '',
        'q34': 'RETURN',
        'q35': 'RETURN',
        'q36': '',
        'q37': '',
        'q38': '',
        'q39': 'VOID',
        'q40': 'VOID',
        'q41': 'MINUS',
        'q42': 'TIMES',
        'q43': 'DIVIDE',
        'q44': '',
        'q45': 'GREATER',
        'q46': 'GREATER_EQUAL',
        'q48' : 'EQUALS',
        'q49': '',
        'q50': 'ATTRIBUTION',
        'q52': '',
        'q53': 'DIFFERENT',
        'q55': 'LPAREN',
        'q56': 'RPAREN',
        'q57': 'LBRACKETS',
        'q58': 'RBRACKETS',
        'q59': 'LBRACES',
        'q60': 'RBRACES',
        'q61': 'SEMICOLON',
        'q62': 'COMMA',
        'qID_START': 'ID',
        'qID_CONT': 'ID',
        'qNUM_START': 'NUMBER',
        'qNUM_CONT': 'NUMBER',
        'qCOMS' : '',
        'qCOMB' : '',
        'qCOME' : ''
    }
)

def preprocess_input(input_string):
    formatted_input = ""
    i = 0

    while i < len(input_string):
        char = input_string[i]
        
        # Verifica se é um operador composto
        if i + 1 < len(input_string) and char in ['<', '>', '!', '=']:
            next_char = input_string[i + 1]
            if next_char == '=':
                formatted_input += f"\n{char}{next_char}\n"
                i += 2  # Pula os dois caracteres
                continue

        #verifica se e comentario
        #abertura de comentário
        if i + 1 < len(input_string) and char in ['/']:
            next_char = input_string[i + 1]
            if next_char == '*':
                formatted_input += f"\n{char}{next_char}\n"
                i += 2
                continue
        
        #fechamento de comentário
        if i + 1 < len(input_string) and char in ['*']:
            next_char = input_string[i + 1]
            if next_char == '/':
                formatted_input += f"\n{char}{next_char}\n"
                i += 2
                continue

        # Se for um delimitador isolado, adiciona espaçamento
        if char in ' (){};,+-*/<>=![]':  
            formatted_input += f" \n{char} \n"
        elif char == ' ':  
            formatted_input += ' '  # Mantém espaços simples
        elif char == '\n':  
            formatted_input += '\n'  # Mantém novas linhas
        else:
            formatted_input += char  # Mantém o caractere

        i += 1  # Avança para o próximo caractere
    
    formatted_input += '\n'
    # print (formatted_input)
    return formatted_input.strip()



def process_input(input_string):
    tokens = []
    current_state = moore.initial_state
    token = ""

    #formatando tokens

    for char in input_string:
        if char in moore.input_alphabet:
            next_state = moore.transitions[current_state].get(char, 'q0')

            if next_state == 'q0':  # Finalizou um token
                if moore.output_table.get(current_state):
                    tokens.append(moore.output_table[current_state])  # Acessa e guarda o output da máquina

                token = ""  # Reinicia o token
                current_state = moore.initial_state
            else:
                token += char  # Continua construindo o token
                current_state = next_state
        else:
            raise IOError(error_handler.newError(char,'ERR-LEX-INV-CHAR'))
            return tokens

    # Garante que o último token seja adicionado
    if moore.output_table.get(current_state):
        tokens.append(moore.output_table[current_state])
    # print(tokens)
    return tokens





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

    if(len(sys.argv) <= 2 and check_key == True):
        raise TypeError(error_handler.newError(check_key, 'ERR-LEX-USE'))

    if not check_cm:
      raise IOError(error_handler.newError(check_key, 'ERR-LEX-NOT-CM'))
    elif not os.path.exists(sys.argv[idx_cm]):
        raise IOError(error_handler.newError(check_key, 'ERR-LEX-FILE-NOT-EXISTS'))
    else:
        data = open(sys.argv[idx_cm])
        source_file = data.read()

        if not check_key:
            print("Definição da Máquina")
            print(moore)
            print("Entrada:")
            print(source_file)
            print("Lista de Tokens:")

        tokens = process_input(preprocess_input(source_file))
        for token in tokens:
            print(token)
        
        # print(moore.get_output_from_string(source_file))

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(e)
    except (ValueError, TypeError):
        print(e)