import random
import string
import sys

def gen():

	strin = ''
	for i in range(32):
		strin += string.upper( hex(random.randint(0,15))[2:] )
	
	return strin+'\n'
		

try:
        hexfile = open(sys.argv[1],'w')
        for i in xrange(int(sys.argv[2])):
                hexfile.write(gen())

        hexfile.close()
	
except Exception:
        print("Usage: python hexgen.py --outputfile --numlines")
