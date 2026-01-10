import re

alpha = 'abcdef'
alphanum = 'abc123'

def cp(msg): # shorten term for "custom print"
    print("[+]", msg)

def fp(msg): # opposite
    print("[-]", msg)

test = 'abc'; test2='123'; test3='def'

# --- tests
'''
What I wanted to imple:
test[i for i in range(3)] in alpha or test[i for i in range], kinda strange grammar, but plz do not care 'bout it.
ㄱㄴㄲ, 리스트 내 각 원소에 대해 다른 리스트에 이들이 포함되는지 비교를 수행하고 싶음. -> 보류

'''



if test or test2 or test3 in alpha:
    cp('detected')
    
    try:
        cp(f"index : ${alpha.index('123')}")
        cp(f"index : ${alpha.index('abc')}")
    except ValueError as e:
        fp(e)
    
# 뭘 하려고 했던 걸까..
    
# --- tests

'''
실험용 텍스트:
홍길동의 주민번호는 800905-1049118 입니다. 
그리고 고길동의 주민번호는 700905-1059119 입니다.
그렇다면 누가 형님일까요?
'''

sample = '''
홍길동의 주민번호는 800905-1049118 입니다. 
그리고 고길동의 주민번호는 700905-1059119 입니다.
그렇다면 누가 형님일까요?
'''

# split into!(개행문자를 공간을 삭제하여 붙이면서 제거하지 않고 분리함, strip이 아닌 split을 쓴 이유..아마?)
for line in sample.split('\n'):
    word = []
    for w in line.split(' '):
        if len(w) == 14 and w[:5+1].isdigit() and w[5+1:].isdigit():
            w = w[:5+1] + '-' + '*'*7
        
        word.append(w)
    print(' '.join(word))

# feel the regex!
res = re.compile("(\d{6})[-]\d{7}")
print(res.sub("\g<1>-*******", sample))