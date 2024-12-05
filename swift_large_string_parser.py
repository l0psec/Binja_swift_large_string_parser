#return HighLevelILcalls
def find_calls(i):
  match i:
     case HighLevelILCall():
         return i

#find all large swift strings with 0x8 discriminator in bridge object
for f in bv.hlil_functions():
  for i in f.traverse(find_calls):
    if "-0x7f" in f"{i}":
      for j in i.params:
        for k in j.operands:
          if "-0x7f" in f"{j}":
            m = hex(int(k) & 0xffffffffffffffff).replace("0x8", "").lstrip("0")
            m = "0x{0}".format(m)
            print(hex(i.address), bv.get_string_at(int(m, 16)+32).raw)
            bv.set_comment_at(i.address, bv.get_string_at(int(m, 16)+32).raw)
