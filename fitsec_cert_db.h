#ifndef fitsec_cert_db_h
#define fitsec_cert_db_h
typedef struct FSCertDB FSCertDB;

typedef enum {
    FSCERTDB_CA,
    FSCERTDB_AT,
    FSCERTDB_OTHERS,

    _FSCERTDB_MAX
}FSCertDBId;

FSCertificate * FSCertDB_Add (FitSec * e, FSCertDBId db, FSCertificate * c);
FSCertificate * FSCertDB_Find(FitSec * e, FSCertDBId db, FSHashedId8 digest);
FSCertificate * FSCertDB_Get (FitSec * e, FSCertDBId db, FSHashedId8 digest);
void            FSCertDB_Del (FitSec * e, FSCertDBId db, FSCertificate * c);
void            FSCertDB_Clean(FitSec * e, FSCertDBId db);
void            FSCertDB_Relink(FitSec * e, FSCertDBId db);


#endif
