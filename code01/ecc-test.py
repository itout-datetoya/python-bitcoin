from ecc import FieldElement

a = FieldElement(7, 13)
b = FieldElement(6, 13)
c = a + b
print(repr(c))

c = a - b
print(repr(c))

c = a * b
print(repr(c))

c = a**b.num
print(repr(c))

c = b / a
print(repr(c))
c = c * a
print(repr(c))
