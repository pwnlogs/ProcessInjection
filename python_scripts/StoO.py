#-----------------------------------------------------------------#
#           Convert string byte code to binary file               #
#-----------------------------------------------------------------#
#   Usage:
#        python StoO.py textFileName

import os

fi = open(sys.argv[1], 'r')
fo = open(os.path.splitext(sys.argv[1])[0] + '.obj', 'wb')

data = ''
byte = fi.read(4)
while byte!='':
    data = data + chr(int(byte[2:4], 16))
    byte = fi.read(4)


newFileByteArray = bytearray(data)
fo.write(newFileByteArray)

fo.close()
fi.close()
