/* iOS SDK: alcune API (system() ecc.) marcate __API_UNAVAILABLE(ios)
   esistono nel runtime — override come vuota per linkerle comunque. */
#define __API_UNAVAILABLE(x)
#define __API_UNAVAILABLE(x,y)
