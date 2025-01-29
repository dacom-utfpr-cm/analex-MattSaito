import string
import sys, os

from automata.fa.Moore import Moore
from myerror import MyError

error_handler = MyError('LexerErrors')

global check_cm
global check_key

moore = Moore(
    states=['q0', 'q1', 'q2', 'q3', 'q4', 'q5', 'q6', 'q7', 'q8', 'q9', 'q10', 'q11', 'q12', 'q13', 'q14', 'q15', 'q16', 'q17', 'q18', 'q19', 'q20', 'q21', 'q22', 'q23',
            'q24', 'q25', 'q26', 'q27', 'q28', 'q29', 'q30', 'q31', 'q32', 'q33', 'q34', 'q35', 'q36', 'q37', 'q38', 'q39', 'q40', 'q41', 'q42', 'q43', 'q44', 'q45', 'q46', 'q47', 'q48',
            'q49', 'q50', 'q51', 'q52', 'q53', 'q54', 'q55', 'q56', 'q57', 'q58', 'q59', 'q60', 'q61', 'q62', 'q63', 'q64', 'q65'],

    input_alphabet=list(string.ascii_letters) + list(string.digits) + ['+', '-', '*', '/', '<', '>', '=', '(', ')', '[', ']', '{', '}', ';', ',', '\n', ' '],

    output_alphabet=['INT', 'ELSE', 'IF', 'WHILE', 'FLOAT', 'RETURN', 'VOID', 'MINUS', 'PLUS', 'TIMES', 'DIVIDE', 'DIFFERENT', 'LPAREN', 'RPAREN', 'NUMBER', 'ID',
                     'LBRACKETS', 'RBRACKETS', 'COMMA', 'LBRACES', 'RBRACES', 'GREATER', 'GREATER_EQUAL', 'LESS', 'LESS_EQUAL', 'EQUALS', 'SEMICOLON', 'ATTRIBUTION'],

    transitions={
        'q0': {
            'w': 'q2', 'i': 'q1', 'e': 'q18', 'f': 'q23', 'r': 'q29', 'v': 'q36', '-': 'q41', '+': 'q3', '*': 'q42', '/': 'q43',
            '!': 'q52', '(': 'q55', ')': 'q56', '[': 'q57', ']': 'q58', '{': 'q59', '}': 'q60', '<': 'q4', '>': 'q44', '=': 'q49',
            ';': 'q61', ',': 'q62', ' ': 'q0', '\n': 'q0'
        },
        'q1': {'n': 'q10'},
        'q2': {'h': 'q5'},
        'q5': {'i': 'q6'},
        'q6': {'l': 'q7'},
        'q7': {'e': 'q8'},
        'q8': {' ': 'q9'},
        'q9': {'\n': 'q0'},
        'q10': {'t': 'q11'},
        'q11': {' ': 'q12'},
        'q12': {'\n': 'q0'},
        'q13': {' ': 'q14'},
        'q14': {'\n': 'q0'},
        'q18': {'l': 'q19'},
        'q19': {'s': 'q20'},
        'q20': {'e': 'q21'},
        'q21': {' ': 'q22'},
        'q22': {'\n': 'q0'},
        'q23': {'l': 'q24'},
        'q24': {'o': 'q25'},
        'q25': {'a': 'q26'},
        'q26': {'t': 'q27'},
        'q27': {' ': 'q28'},
        'q28': {'\n': 'q0'},
        'q29': {'e': 'q30'},
        'q30': {'t': 'q31'},
        'q31': {'u': 'q32'},
        'q32': {'r': 'q33'},
        'q33': {'n': 'q34'},
        'q34': {' ': 'q35'},
        'q35': {'\n': 'q0'},
        'q36': {'o': 'q37'},
        'q37': {'i': 'q38'},
        'q38': {'d': 'q39'},
        'q39': {' ': 'q40'},
        'q40': {'\n': 'q0'},
        'q41': {' ': 'q41_END'},
        'q41_END': {'\n': 'q0'},
        'q42': {' ': 'q42_END'},
        'q42_END': {'\n': 'q0'},
        'q43': {' ': 'q43_END'},
        'q43_END': {'\n': 'q0'},
        'q44': {'=': 'q47', ' ': 'q45'},
        'q45': {' ': 'q45_END'},
        'q45_END': {'\n': 'q0'},
        'q47': {' ': 'q47_END'},
        'q47_END': {'\n': 'q0'},
        'q49': {' ': 'q49_END'},
        'q49_END': {'\n': 'q0'},
        'q52': {'=': 'q53'},
        'q53': {' ': 'q53_END'},
        'q53_END': {'\n': 'q0'},
        'q55': {' ': 'q55_END'},
        'q55_END': {'\n': 'q0'},
        'q56': {' ': 'q56_END'},
        'q56_END': {'\n': 'q0'},
        'q57': {' ': 'q57_END'},
        'q57_END': {'\n': 'q0'},
        'q58': {' ': 'q58_END'},
        'q58_END': {'\n': 'q0'},
        'q59': {' ': 'q59_END'},
        'q59_END': {'\n': 'q0'},
        'q60': {' ': 'q60_END'},
        'q60_END': {'\n': 'q0'},
        'q61': {' ': 'q61_END'},
        'q61_END': {'\n': 'q0'},
        'q62': {' ': 'q62_END'},
        'q62_END': {'\n': 'q0'}
    },
    initial_state='q0',
    output_table={
        'q0': '',
        'q1': '',
        'q2': '',
        'q5': '',
        'q6': '',
        'q7': '',
        'q8': 'WHILE',
        'q9': 'WHILE',
        'q10': '',
        'q11': 'INT',
        'q12': 'INT',
        'q13': 'IF',
        'q14': 'IF',
        'q18': '',
        'q19': '',
        'q20': '',
        'q21': 'ELSE',
        'q22': 'ELSE',
        'q23': '',
        'q24': '',
        'q25': '',
        'q26': '',
        'q27': '',
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
        'q41_END': 'MINUS',
        'q42': 'TIMES',
        'q42_END': 'TIMES',
        'q43': 'DIVIDE',
        'q43_END': 'DIVIDE',
        'q44': '',
        'q45': 'GREATER',
        'q45_END': 'GREATER',
        'q47': 'GREATER_EQUAL',
        'q47_END': 'GREATER_EQUAL',
        'q49': 'EQUALS',
        'q49_END': 'EQUALS',
        'q52': '',
        'q53': 'DIFFERENT',
        'q53_END': 'DIFFERENT',
        'q55': 'LPAREN',
        'q55_END': 'LPAREN',
        'q56': 'RPAREN',
        'q56_END': 'RPAREN',
        'q57': 'LBRACKETS',
        'q57_END': 'LBRACKETS',
        'q58': 'RBRACKETS',
        'q58_END': 'RBRACKETS',
        'q59': 'LBRACES',
        'q59_END': 'LBRACES',
        'q60': 'RBRACES',
        'q60_END': 'RBRACES',
        'q61': 'SEMICOLON',
        'q61_END': 'SEMICOLON',
        'q62': 'COMMA',
        'q62_END': 'COMMA'
    }
)

def preprocess_input(input_string):
    # Add newlines around certain characters to format the input correctly
    formatted_input = ""
    for line in input_string.splitlines():
        line = line.replace('(', '\n(\n').replace(')', '\n)\n').replace('{', '\n{\n').replace('}', '\n}\n').replace(';', '\n;\n').replace(',', '\n,\n')
        formatted_input += line.strip() + "\n"
        # print(formatted_input)
    return formatted_input.strip()

def process_input(input_string):
    tokens = []
    current_state = moore.initial_state
    token = ""
    
    for char in input_string:
        if char in moore.input_alphabet:
            next_state = moore.transitions[current_state].get(char, 'q0')
            if next_state == 'q0' and current_state != 'q0':
                if moore.output_table[current_state]:
                    tokens.append(moore.output_table[current_state])
                current_state = moore.initial_state
            else:
                current_state = next_state
        else:
            error_handler.handle_error(f"Unexpected character: {char}")
            return tokens
    
    if moore.output_table[current_state]:
        tokens.append(moore.output_table[current_state])
    
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

        tokens = process_input(preprocess_input(source_file))
        for token in tokens:
            print(token)
        
        print(moore.get_output_from_string(source_file))
    # if len(sys.argv) != 3 or sys.argv[1] != '-k':
    #     print("Usage: python analex.py -k <filename>")
    #     sys.exit(1)

    # filename = sys.argv[2]
    # if not os.path.isfile(filename):
    #     print(f"File not found: {filename}")
    #     sys.exit(1)

    # with open(filename, 'r') as file:
    #     input_string = file.read()

    # formatted_input = preprocess_input(input_string)
    # tokens = process_input(formatted_input)
    # for token in tokens:
    #     print(token)

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(e)
    except (ValueError, TypeError):
        print(e)