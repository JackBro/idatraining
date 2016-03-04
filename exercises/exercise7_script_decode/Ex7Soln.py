def decode():
    var_5 = 0x5A
    var_4 = 0x80495C0
    
    while True:
        eax = 0xFF & Dword(var_4)
        eax = eax ^ var_5

        if eax == 0:
            break
            
        Message("%c" % eax)
        var_5 = 0xFF & Dword(var_4)
        var_4 += 1
    
decode()


