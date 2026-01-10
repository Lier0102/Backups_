import textwrap
import random

text = "I think this is the long text that I could write here for the test." * 10 # << 여기까진 리스트 X
result = textwrap.wrap(text, width=70) # 리스트 객체 반환하는 듯 보임

print("list length :", len(result))

print("length for idx 0 :", len(result[0]))
print('\n'); print('other dumps? >>\n')
print(textwrap.shorten(result[0], width=15) + ', ', result[1:])

print("Wanna Simplify? Here:\n\n") # total '\n'*3 due to print() default arg
print('\n'.join(result)) # each index, they are seperated by '\n'
# tlqkf