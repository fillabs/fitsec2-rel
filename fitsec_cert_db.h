#ifndef fitsec_cert_db_h
#define fitsec_cert_db_h

#include "fitsec.h"

typedef struct FSCertDB FSCertDB;

typedef enum {
    FSCERTDB_CA,
    FSCERTDB_AT,
    FSCERTDB_OTHERS,

    _FSCERTDB_MAX
}FSCertDBId;

FITSEC_EXPORT
FSCertificate * FSCertDB_Add (FitSec * e, FSCertDBId db, FSCertificate * c);
FITSEC_EXPORT
FSCertificate * FSCertDB_Find(FitSec * e, FSCertDBId db, FSHashedId8 digest);
FITSEC_EXPORT
FSCertificate * FSCertDB_Get (FitSec * e, FSCertDBId db, FSHashedId8 digest);
FITSEC_EXPORT
void            FSCertDB_Del (FitSec * e, FSCertDBId db, FSCertificate * c);
FITSEC_EXPORT
void            FSCertDB_Clean(FitSec * e, FSCertDBId db);
FITSEC_EXPORT
void            FSCertDB_Relink(FitSec * e, FSCertDBId db);
FITSEC_EXPORT
void            FSCertDB_Splay(FSCertificate *c);

#define FSCertDB_ForEach(e,db,c) \
    for(void * __last_ ## c, *c = _FSCertDB_NextNode_Init(e, db, &__last_ ## c); \
        c; \
        c = _FSCertDB_NextNode(c, &__last_ ## c))        
FITSEC_EXPORT
FSCertificate * _FSCertDB_NextNode_Init(FitSec * e, FSCertDBId db, void ** px);
FITSEC_EXPORT
FSCertificate * _FSCertDB_NextNode(const FSCertificate * c, void ** px);

#endif
