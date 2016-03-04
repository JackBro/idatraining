
#include <idc.idc>

static createImportName() {
   auto name = Name(EAX);
   if (name[0:6] == "ws2_32") {
      name = name[8:];
   }
   else {
      name = substr(name, strstr(name, "_") + 1, -1);
   }
   MakeNameEx(EBX, name, 0);
   return 0;  //don't stop
}

static main() {
   AddBpt(0x00407861);
   SetBptCnd(0x00407861, "createImportName()");
}


