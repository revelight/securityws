import re
import math
from collections import Counter


#                              usage
# -------------------------------------------------------------------------


ML_CLASS_CODE = 'CODE'
ML_CLASS_EMAIL = 'EMAIL'


def email_code_ML_classifier(text):
    print('ML classifying...')
    ml_class = dt_decider(vectorize(text))
    print('\n===> CLASSIFICATION : {} <===\n'.format(ml_class))
    return ml_class

#                           text vectorization
# -------------------------------------------------------------------------

def vectorize(text):

    # --- ADJUST CRITICAL-TOKENS WEIGHTS HERE ---
    def adjust(k,v):
        if k=='int':
            v = v + 3
        return v

    tokenized_text = analyzer(text)
    cnt = Counter(tokenized_text)
    vec = {k: (v * vec_idfs[vec_volc[k]]) for k, v in cnt.items() if k in vec_volc}
    norm2 = math.sqrt(sum(v * v for v in vec.values()))
    vec = {k: (v / norm2) for k, v in vec.items()}
    vec = {k: (adjust(k,v)) for k, v in vec.items()}
    return vec



#                           text tokenization
# -------------------------------------------------------------------------
# doc string to doc string
def preprocessText(text):
    return text.lower()

# doc string to doc token list
TOKEN_DELIMS = '[^\w\']|\s'
TOKEN_MIN_LEN = 2
TOKEN_STOPWORDS = {'enron', 'for', '<', '>', 'a', 'subject', 'to', 'from'}
TOKEN_NUMERIC = ''
TOKEN_DATASET_NUMERIC = 'LONGNUM'  # dataset numeric after stripping


def tokenizer(text):

    def normalizeToken(tk):
        return tk

    def getToken(tk):
        if len(tk) < TOKEN_MIN_LEN:
            return None
        if tk == TOKEN_DATASET_NUMERIC or str.isnumeric(tk):
            return TOKEN_NUMERIC
        if tk in TOKEN_STOPWORDS:
            return None
        return tk

    text = re.split(TOKEN_DELIMS, text)
    tokens = [getToken(word) for word in text]
    tokens = [tk for tk in tokens if tk]
    return tokens

# doc string to doc token list
def analyzer(text):
    return tokenizer(preprocessText(text))

# -------------------------------------------------------------------------



#                decision tree machine learning classifier
# -------------------------------------------------------------------------
def dt_decider(vec_dict):
    if vec_dict.get('int', 0) > 0.0123351290822:
        if vec_dict.get('please', 0) > 0.00419167522341:
            if vec_dict.get('int', 0) > 0.457087785006:
                return 'CODE' # --> (1.0000, 6.00/6.00 examples)
            else: # below threshold for 'int'
                return 'EMAIL' # --> (1.0000, 215.00/215.00 examples)
        else: # below threshold for 'please'
            if vec_dict.get('we', 0) > 0.0554827749729:
                if vec_dict.get('main', 0) > 0.0099976612255:
                    return 'CODE' # --> (1.0000, 27.00/27.00 examples)
                else: # below threshold for 'main'
                    if vec_dict.get('be', 0) > 0.331199407578:
                        return 'CODE' # --> (1.0000, 1.00/1.00 examples)
                    else: # below threshold for 'be'
                        return 'EMAIL' # --> (1.0000, 66.00/66.00 examples)
            else: # below threshold for 'we'
                if vec_dict.get('message', 0) > 0.0984009876847:
                    if vec_dict.get('main', 0) > 0.0429555773735:
                        return 'CODE' # --> (1.0000, 3.00/3.00 examples)
                    else: # below threshold for 'main'
                        return 'EMAIL' # --> (1.0000, 27.00/27.00 examples)
                else: # below threshold for 'message'
                    if vec_dict.get('ect', 0) > 0.00942249875516:
                        return 'EMAIL' # --> (0.9412, 16.00/17.00 examples)
                    else: # below threshold for 'ect'
                        return 'CODE' # --> (0.9997, 131343.00/131379.00 examples)
    else: # below threshold for 'int'
        if vec_dict.get('do', 0) > 0.572423696518:
            if vec_dict.get('if', 0) > 0.025615233928:
                if vec_dict.get('you', 0) > 0.0554434135556:
                    return 'EMAIL' # --> (1.0000, 18.00/18.00 examples)
                else: # below threshold for 'you'
                    if vec_dict.get('the', 0) > 0.0554221719503:
                        return 'EMAIL' # --> (1.0000, 9.00/9.00 examples)
                    else: # below threshold for 'the'
                        return 'CODE' # --> (0.9951, 1210.00/1216.00 examples)
            else: # below threshold for 'if'
                if vec_dict.get('do', 0) > 0.833772301674:
                    if vec_dict.get('the', 0) > 0.0276307333261:
                        return 'EMAIL' # --> (1.0000, 14.00/14.00 examples)
                    else: # below threshold for 'the'
                        return 'CODE' # --> (0.8547, 153.00/179.00 examples)
                else: # below threshold for 'do'
                    if vec_dict.get('while', 0) > 0.102305486798:
                        return 'CODE' # --> (1.0000, 39.00/39.00 examples)
                    else: # below threshold for 'while'
                        return 'EMAIL' # --> (0.9257, 498.00/538.00 examples)
        else: # below threshold for 'do'
            if vec_dict.get('if', 0) > 0.44429987669:
                if vec_dict.get('you', 0) > 0.0881758108735:
                    return 'EMAIL' # --> (1.0000, 57.00/57.00 examples)
                else: # below threshold for 'you'
                    if vec_dict.get('the', 0) > 0.0964298546314:
                        return 'EMAIL' # --> (1.0000, 30.00/30.00 examples)
                    else: # below threshold for 'the'
                        return 'CODE' # --> (0.8966, 520.00/580.00 examples)
            else: # below threshold for 'if'
                if vec_dict.get('ans', 0) > 0.158078372478:
                    if vec_dict.get('the', 0) > 0.123117119074:
                        return 'EMAIL' # --> (0.8889, 8.00/9.00 examples)
                    else: # below threshold for 'the'
                        return 'CODE' # --> (1.0000, 319.00/319.00 examples)
                else: # below threshold for 'ans'
                    if vec_dict.get('main', 0) > 0.194814741611:
                        return 'CODE' # --> (0.6118, 312.00/510.00 examples)
                    else: # below threshold for 'main'
                        return 'EMAIL' # --> (0.9963, 257417.00/258378.00 examples)

# -------------------------------------------------------------------------


# ---- Model data -----------

vec_idfs = [ 2.55678389,  2.47940697,  2.67818712,  1.79849697,  3.16314064,
        2.56664143,  2.23685888,  2.40706037,  2.28214076,  2.13620968,
        2.92453411,  2.23538104,  2.6761483 ,  2.4369891 ,  2.6732603 ,
        2.43442678,  3.04199952,  2.62816475,  2.95247574,  2.80903008,
        2.92152727,  2.64099471,  3.52671481,  2.93057505,  3.57727227,
        2.8068149 ,  2.1130335 ,  3.49616279,  3.02011935,  3.46421468,
        1.51700431,  1.83515507,  2.50473049,  2.09266766,  1.93150994,
        2.26064507,  3.62129099,  3.37437305,  2.509765  ,  3.25981295,
        2.08439109,  2.97719431,  2.47308082,  2.91738812,  3.22428193,
        2.24723006,  2.88425883,  3.09893226,  2.45522046,  1.87667565,
        1.88733549,  2.4226923 ,  2.79633248,  2.80196794,  2.23133471,
        2.51539134,  3.59070252,  2.19180576,  4.18875518,  2.97510483,
        3.27208245,  2.24064654,  2.1639956 ,  1.62883383,  3.18962974,
        2.02282108,  2.87197875,  3.4375205 ,  2.94298028,  2.14651015,
        2.85645957,  2.99479723,  2.31976804,  2.60421327,  2.24445741,
        2.20356981,  2.78069897,  3.77110115,  1.87476072,  2.42374669]

vec_volc = {'is': 34, 'our': 52, 'have': 26, 'the': 63, 'out': 53, 'of': 49, 'if': 30, 'you': 78, 'would': 76, 'any': 5, 'and': 3, 'on': 50, 'or': 51, 'as': 7, 'it': 35, 'be': 9, 'more': 44, 'not': 48, 'are': 6, 'in': 31, 'time': 66, 'can': 12, 'me': 42, 'your': 79, 'that': 62, 'please': 54, 'cc': 13, 'with': 75, 'com': 15, 'by': 11, 'hou': 28, 'ect': 20, 'pm': 55, 'corp': 16, 'am': 1, 'mail': 39, 'has': 25, 'new': 46, 'we': 72, 'at': 8, 'but': 10, 'this': 65, 'will': 74, 'all': 0, 'do': 19, 'may': 41, 'an': 2, 'gas': 24, 'was': 71, 'no': 47, 'long': 38, 'include': 32, 'up': 68, 'he': 27, 'said': 58, 'http': 29, 'www': 77, 'else': 21, 'they': 64, 'size': 60, 'return': 57, 'first': 23, 'using': 69, 'while': 73, 'message': 43, 'power': 56, 'its': 36, 'energy': 22, 'main': 40, 'define': 18, 'll': 37, 'int': 33, 'cin': 14, 'std': 61, 'ans': 4, 'namespace': 45, 'vector': 70, 'typedef': 67, 'cout': 17, 'scanf': 59}
