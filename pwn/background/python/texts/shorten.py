import textwrap

a = "Life is too short, you need python"
b = textwrap.shorten(a, width=15)
c = "To be or not to be. That's the problem."
d = textwrap.shorten(c, width=15)

print(b)
print(d)