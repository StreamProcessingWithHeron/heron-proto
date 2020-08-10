from prettytable import PrettyTable

def format_print(size, header, type_size, type_str,
                 REQID_str, data_size, data_str):
  tbl = PrettyTable(['key', 'value (len in bytes)'])
  tbl.align['key'] = 'r'
  tbl.align['value (len in bytes)'] = 'l'
  tbl.add_row(['payload len', size+'=4+'+header])
  tbl.add_row(['heron len', 
               header+'=4+'+type_size+'+32+4+'+data_size])
  tbl.add_row(['proto_type len', type_size])
  tbl.add_row(['proto_type str', type_str])
  tbl.add_row(['REQID', REQID_str])
  tbl.add_row(['proto_data len', data_size])
  tbl.add_row(['proto_data str', 
               data_str.decode('ascii').rstrip()])
  return str(tbl)+'\n'