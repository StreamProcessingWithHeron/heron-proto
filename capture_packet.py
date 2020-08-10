from netifaces import *
from scapy.all import *
from struct import unpack
from sys import argv

from parse_message import heron_parse

deduplicate = set() 
buf_map = dict() 

def is_anchor(bin): 
  try:
    (total_len,) = unpack('!i', bin[0:4])
    (type_len,) = unpack('!i', bin[4:8])
    type_str = bin[8:8+type_len].decode('ascii')
    if not type_str.startswith('heron.proto.'): 
      raise ValueError('unknown proto type prefix %s' % type_str)
    REQID_str = bin[8+type_len:40+type_len].hex()
    (data_len,) = unpack('!i', bin[40+type_len:44+type_len])
    valid = True
  except Exception as e:
    print(e)
    valid = False 
  return valid

def trial_capture(key, bin, seq):
  ret = '------------\n'+key+'('+str(len(bin))+')\n'
  if (seq in deduplicate): 
    deduplicate.discard(seq)
    return ret + "duplicated TCP sequence\n"
  else:
    deduplicate.add(seq)

  if is_anchor(bin):
    ret += 'anchor heron packet\n'
    buf_map[key] = bytearray() 

  if key in buf_map:
    buf_map[key].extend(bin)
    ret += bytes(buf_map[key]).hex()+'\n'
    while len(buf_map[key])>=4+4+32+4: 
      (total_len,) = unpack('!i', buf_map[key][0:4])
      if len(buf_map[key])<4+total_len: 
        ret += ('required '+str(4+total_len)+
                '; buffered '+str(len(buf_map[key]))+'\n')
        break
      ret += heron_parse(bytes(buf_map[key][0:4+total_len])) 
      buf_map[key] = buf_map[key][4+total_len:] 
  else:
    ret += 'unanchored packet\n'
  return ret

sniff(iface=list(filter(lambda x: AF_INET in ifaddresses(x),
                        interfaces())), 
      filter='greater 75 and tcp port '+argv[1], 
      prn=lambda x: trial_capture(
          x.sprintf('%TCP.sport%->%TCP.dport%'), 
          bytes(x[TCP].payload), bytes(x[TCP].seq)))