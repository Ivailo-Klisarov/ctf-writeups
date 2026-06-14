from pwn import *
import re
from math import *
host = "178.105.199.41"
port = 22222
i = 1
equation = ""
r = remote(host, port)
while i <= 400:
        if("Question" in r.recvline().decode().strip()):
                question = r.recvline().decode().strip()
                if("OpenAI" in question):
                        r.sendline("I am a human")
                elif("floored" in question):
                        print(question)
                        print("FLOORED")
                        question = question.replace("divided by", "/")
                        for c in question:
                                if c in "1234567890()+-/*":
                                        equation += c
                        print(floor(int(eval(equation.replace("divided by", "/")))))
                        r.sendline(str(floor(int(eval(equation.replace("divided by", "/"))))).encode())
                elif("floor(" in question):
                        print(question)
                        print("FLOOR")
                        for c in question:
                                if c in "1234567890()+-/*":
                                        equation += c
                        print(floor(int(eval(equation))))
                        r.sendline(str(floor(int(eval(equation)))).encode())
                else:
                        print(question)
                        for c in question:
                                if c in "1234567890()+-/*":
                                        equation += c
                        r.sendline(str(eval(equation)).encode())
                        print(str(eval(equation)).encode())
                #break
        i=i+1
        equation = ""
print(r.recvline().decode().strip())
print(r.recvline().decode().strip())
print(r.recvline().decode().strip())
print(r.recvline().decode().strip())
