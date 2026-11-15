/* iOS SDK: alcune API (system() ecc.) marcate __API_UNAVAILABLE(ios)
   esistono nel runtime — override variadic come vuota per linkerle comunque. */
#define __API_UNAVAILABLE(...)
