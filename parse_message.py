from struct import unpack
from subprocess import PIPE, Popen

from print_table import format_print

def heron_parse(bin):
  (total_len,) = unpack('!i', bin[0:4]) 
  (type_len,) = unpack('!i', bin[4:8]) 
  type_str = bin[8:8+type_len].decode('ascii') 
  REQID_str = bin[8+type_len:40+type_len].hex() 
  (data_len,) = unpack('!i', bin[40+type_len:44+type_len]) 
  data_bin = bin[44+type_len:44+type_len+data_len] 

  cmd = ('grep -l '+
         type_str.split('.')[-1]+' ' 
         '/home/ubuntu/heron/heron/proto/*.proto\n') 
  ret = cmd
  p = Popen(cmd, stdin=PIPE, stdout=PIPE, stderr=PIPE,
            shell=True, text=True)
  (PROTO_FILES, err) = p.communicate() 
  if err != '':
    return ret + err + format_print(
      str(len(bin)), str(total_len), str(type_len), 
      type_str, REQID_str, str(data_len), b'')
  ret += PROTO_FILES

  cmd = ('/home/ubuntu/protoc/bin/protoc '+ 
         '--decode='+type_str+' '+ 
         '--proto_path=/home/ubuntu/heron/heron/proto/ '+ 
         PROTO_FILES) 
  ret += cmd
  p = Popen(cmd, 
    stdin=PIPE, stdout=PIPE, stderr=PIPE, shell=True)
  (data_str, err) = p.communicate(data_bin) 
  if err != b'':
    return ret + str(err) + format_print(
      str(len(bin)), str(total_len), str(type_len), 
      type_str, REQID_str, str(data_len), data_str)
  return ret + format_print(
    str(len(bin)), str(total_len), str(type_len), 
    type_str, REQID_str, str(data_len), data_str)