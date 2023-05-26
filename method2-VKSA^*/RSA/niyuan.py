def exgcd(a, b, x, y):
  if b == 0:
      x, y = 1, 0
      return
  exgcd(b, a % b, y, x)
  y = y - (a // b * x)

a = exgcd(11,8,)
print(a)