#-----------------------------------------------------------------#
#           Convert binary files to string byte code              #
#-----------------------------------------------------------------#
#   Usage:
#        python OtoS.py binaryFileName start end
#   Here, start is an optional argument stating 
#              how many bytes should be neglected in the begining
#         end is an optional argumrnt stating
#              how many butes should be neglected at the end

import sys

start = int(sys.argv[2]) if len(sys.argv)>2 else 0
end   = 4*int(sys.argv[3]) if len(sys.argv)>3 else 0

s = ''
with open(sys.argv[1], "rb") as f:
    waste = f.read(start)
    byte = f.read(1)
    while byte != "":
        s = s+'\\x'+(str(hex(int(ord(byte))))[2:4]).zfill(2)
        byte = f.read(1)
s = s[:-end]


fo = open(sys.argv[1]+".txt", "w")
fo.write(s)

fo.close()
# fi.close()
