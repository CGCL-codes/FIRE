import re
import Levenshtein
from loguru import logger
from collections import Counter

def isphor(s, liter):
    m = re.search(liter, s)
    if m is not None:
        return True
    else:
        return False


def doubisphor(forward, back):
    double = (
    '->', '--', '-=', '+=', '++', '>=', '<=', '==', '!=', '*=', '/=', '%=', '/=', '&=', '^=', '||', '&&', '>>', '<<')
    string = forward + back

    if string in double:
        return True
    else:
        return False


def trisphor(s, t):
    if (s == '>>') | (s == '<<') and (t == '='):
        return True
    else:
        return False


def create_tokens(sentence):
    formal = '^[_a-zA-Z][_a-zA-Z0-9]*$'
    phla = '[^_a-zA-Z0-9]'
    space = '\s'
    spa = ''
    string = []
    j = 0
    str = sentence
    i = 0

    while (i < len(str)):
        if isphor(str[i], space):
            if i > j:
                string.append(str[j:i])
                j = i + 1
            else:
                j = i + 1

        elif isphor(str[i], phla):
            if (i + 1 < len(str)) and isphor(str[i + 1], phla):
                m = doubisphor(str[i], str[i + 1])

                if m:
                    string1 = str[i] + str[i + 1]

                    if (i + 2 < len(str)) and (isphor(str[i + 2], phla)):
                        if trisphor(string1, str[i + 2]):
                            string.append(str[j:i])
                            string.append(str[i] + str[i + 1] + str[i + 2])
                            j = i + 3
                            i = i + 2

                        else:
                            string.append(str[j:i])
                            string.append(str[i] + str[i + 1])
                            string.append(str[i + 2])
                            j = i + 3
                            i = i + 2

                    else:
                        string.append(str[j:i])
                        string.append(str[i] + str[i + 1])
                        j = i + 2
                        i = i + 1

                else:
                    string.append(str[j:i])
                    string.append(str[i])
                    if str[i] != ';':
                        string.append(str[i + 1])
                        j = i + 2
                        i = i + 1
                    else:
                        j = i + 1

            else:
                string.append(str[j:i])
                string.append(str[i])
                j = i + 1

        i = i + 1

    count = 0
    count1 = 0
    sub0 = '\r'

    if sub0 in string:
        string.remove('\r')

    for sub1 in string:
        if sub1 == ' ':
            count1 = count1 + 1

    for j in range(count1):
        string.remove(' ')

    for sub in string:
        if sub == spa:
            count = count + 1

    for i in range(count):
        string.remove('')

    return string



def get_fea(file_path):
    try:
        with open(file_path, "r", encoding='utf-8') as f:
            gadget = f.read()
            f.close()

        # final feature dictionary
        tokens_list = []

        # regular expression to catch a-line comment
        rx_comment = re.compile('\*/\s*$')
        gadget = gadget.split('\n')

        for line in gadget:
            # process if not the header line and not a multi-line commented line
            if rx_comment.search(line) is None:

                # replace any non-ASCII characters with empty string
                ascii_line = re.sub(r'[^\x00-\x7f]', r'', line)
                nostrlit_line = re.sub(r'".*?"', '""', ascii_line)
                nocharlit_line = re.sub(r"'.*?'", "''", nostrlit_line)

                # tokenlization
                tokens = create_tokens(nocharlit_line)
                #tokenslist.extend(tokens)
                tokens_list.extend(tokens)
        return file_path, tokens_list
    except UnicodeDecodeError:
        pass


def get_fea_code(gadget):
    try:
        # final feature dictionary
        tokens_list = []

        # regular expression to catch a-line comment
        rx_comment = re.compile('\*/\s*$')
        gadget = gadget.split('\n')
        for line in gadget:
            # process if not the header line and not a multi-line commented line
            if rx_comment.search(line) is None:

                # replace any non-ASCII characters with empty string
                ascii_line = re.sub(r'[^\x00-\x7f]', r'', line)
                nostrlit_line = re.sub(r'".*?"', '""', ascii_line)
                nocharlit_line = re.sub(r"'.*?'", "''", nostrlit_line)

                # tokenlization
                tokens = create_tokens(nocharlit_line)
                tokens_list.extend(tokens)

        return tokens_list
    except UnicodeDecodeError:
        pass


def jaccard_sim(list1, list2):
    counter1 , counter2 = Counter(list1), Counter(list2)
    set1,set2 = set(list1), set(list2)

    intersection_size = sum((min(counter1[x], counter2[x]) for x in set1.intersection(set2)))
    union_size = sum((max(counter1[x], counter2[x]) for x in set1.union(set2)))

    similarity = intersection_size / union_size if union_size != 0 else 0

    return similarity

def Jaro_sim(group1, group2):


    sim = Levenshtein.jaro(group1, group2)
    return sim


def Jaro_winkler_sim(group1, group2):

    sim = Levenshtein.jaro_winkler(group1, group2)
    return sim


def Levenshtein_sim(group1, group2):

    distance = Levenshtein.distance(group1, group2)
    return distance


def Levenshtein_ratio(group1, group2):

    sim = Levenshtein.ratio(group1, group2)
    return sim


def get_similarity(funtokens, t, vulnandtokens):
    vuln, vulntokens = vulnandtokens
    
    try:        
        sim = jaccard_sim(funtokens, vulntokens)
        if sim >= t:
            return vuln
    except Exception as e:
        logger.error(f"get_similarity failed : {str(e)}")


    
