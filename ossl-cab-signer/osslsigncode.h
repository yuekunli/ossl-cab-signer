/*
 * Copyright (C) 2021-2023 Michał Trojnara <Michal.Trojnara@stunnel.org>
 * Author: Małgorzata Olszówka <Malgorzata.Olszowka@stunnel.org>
 */


#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>

//#include <ctype.h>
//#include <errno.h>
//#include <fcntl.h>
//#include <stdbool.h>
//#include <stdint.h>
//#include <stdio.h>
//#include <stdlib.h>
//#include <string.h>
//#include <time.h>


//#include <sys/types.h>
#include <sys/stat.h>

#include <openssl/asn1t.h>
#include <openssl/bio.h>
//#include <openssl/bn.h>

//#include <openssl/conf.h>
//#include <openssl/crypto.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>

#include <openssl/pkcs7.h>
#include <openssl/pkcs12.h>

//#include <openssl/provider.h>

//#include <openssl/rand.h>
#include <openssl/safestack.h>
//#include <openssl/ssl.h>
//#include <openssl/ts.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h> /* X509_PURPOSE */



#ifdef WIN32
#define remove_file(filename) _unlink(filename)
#else
#define remove_file(filename) unlink(filename)
#endif /* WIN32 */

#define GET_UINT8_LE(p) ((const u_char *)(p))[0]

#define GET_UINT16_LE(p) (uint16_t)(((const u_char *)(p))[0] | \
                                   (((const u_char *)(p))[1] << 8))

#define GET_UINT32_LE(p) (uint32_t)(((const u_char *)(p))[0] | \
                                   (((const u_char *)(p))[1] << 8) | \
                                   (((const u_char *)(p))[2] << 16) | \
                                   (((const u_char *)(p))[3] << 24))

#define PUT_UINT8_LE(i, p) ((u_char *)(p))[0] = (u_char)((i) & 0xff);

#define PUT_UINT16_LE(i,p) ((u_char *)(p))[0] = (u_char)((i) & 0xff); \
                           ((u_char *)(p))[1] = (u_char)(((i) >> 8) & 0xff)

#define PUT_UINT32_LE(i,p) ((u_char *)(p))[0] = (u_char)((i) & 0xff); \
                           ((u_char *)(p))[1] = (u_char)(((i) >> 8) & 0xff); \
                           ((u_char *)(p))[2] = (u_char)(((i) >> 16) & 0xff); \
                           ((u_char *)(p))[3] = (u_char)(((i) >> 24) & 0xff)


#define SIZE_64K 65536       /* 2^16 */
#define SIZE_16M 16777216    /* 2^24 */

/*
 * Macro names:
 * linux:  __BYTE_ORDER == __LITTLE_ENDIAN | __BIG_ENDIAN
 *           BYTE_ORDER == LITTLE_ENDIAN | BIG_ENDIAN
 * bsd:     _BYTE_ORDER == _LITTLE_ENDIAN | _BIG_ENDIAN
 *           BYTE_ORDER == LITTLE_ENDIAN | BIG_ENDIAN
 * solaris: _LITTLE_ENDIAN | _BIG_ENDIAN
 */

#ifndef BYTE_ORDER
#define LITTLE_ENDIAN    1234
#define BIG_ENDIAN       4321
#define BYTE_ORDER       LITTLE_ENDIAN
#endif /* BYTE_ORDER */

#if !defined(BYTE_ORDER) || !defined(LITTLE_ENDIAN) || !defined(BIG_ENDIAN)
#error "Cannot determine the endian-ness of this platform"
#endif

#ifndef LOWORD
#define LOWORD(x) ((x) & 0xFFFF)
#endif /* LOWORD */
#ifndef HIWORD
#define HIWORD(x) (((x) >> 16) & 0xFFFF)
#endif /* HIWORD */

#if BYTE_ORDER == BIG_ENDIAN
#define LE_UINT16(x) ((((x) >> 8) & 0x00FF) | \
                     (((x) << 8) & 0xFF00))
#define LE_UINT32(x) (((x) >> 24) | \
                     (((x) & 0x00FF0000) >> 8) | \
                     (((x) & 0x0000FF00) << 8) | \
                     ((x) << 24))
#else
#define LE_UINT16(x) (x)
#define LE_UINT32(x) (x)
#endif /* BYTE_ORDER == BIG_ENDIAN */


#define INVALID_TIME ((time_t)-1)

/* Microsoft OID Authenticode */
#define SPC_INDIRECT_DATA_OBJID      "1.3.6.1.4.1.311.2.1.4"
#define SPC_STATEMENT_TYPE_OBJID     "1.3.6.1.4.1.311.2.1.11"
#define SPC_SP_OPUS_INFO_OBJID       "1.3.6.1.4.1.311.2.1.12"
#define SPC_PE_IMAGE_DATA_OBJID      "1.3.6.1.4.1.311.2.1.15"
#define SPC_CAB_DATA_OBJID           "1.3.6.1.4.1.311.2.1.25"
#define SPC_SIPINFO_OBJID            "1.3.6.1.4.1.311.2.1.30"
#define SPC_PE_IMAGE_PAGE_HASHES_V1  "1.3.6.1.4.1.311.2.3.1" /* SHA1 */
#define SPC_PE_IMAGE_PAGE_HASHES_V2  "1.3.6.1.4.1.311.2.3.2" /* SHA256 */
#define SPC_NESTED_SIGNATURE_OBJID   "1.3.6.1.4.1.311.2.4.1"
/* Microsoft OID Time Stamping */
#define SPC_TIME_STAMP_REQUEST_OBJID "1.3.6.1.4.1.311.3.2.1"
#define SPC_RFC3161_OBJID            "1.3.6.1.4.1.311.3.3.1"
/* Microsoft OID Crypto 2.0 */
#define MS_CTL_OBJID                 "1.3.6.1.4.1.311.10.1"
/* Microsoft OID Catalog */
#define CAT_NAMEVALUE_OBJID          "1.3.6.1.4.1.311.12.2.1"
/* Microsoft OID Microsoft_Java */
#define MS_JAVA_SOMETHING            "1.3.6.1.4.1.311.15.1"

#define SPC_UNAUTHENTICATED_DATA_BLOB_OBJID  "1.3.6.1.4.1.42921.1.2.1"

/* Public Key Cryptography Standards PKCS#9 */
#define PKCS9_MESSAGE_DIGEST         "1.2.840.113549.1.9.4"
#define PKCS9_SIGNING_TIME           "1.2.840.113549.1.9.5"
#define PKCS9_COUNTER_SIGNATURE      "1.2.840.113549.1.9.6"
#define PKCS9_SEQUENCE_NUMBER        "1.2.840.113549.1.9.25.4"

/* WIN_CERTIFICATE structure declared in Wintrust.h */
#define WIN_CERT_REVISION_2_0           0x0200
#define WIN_CERT_TYPE_PKCS_SIGNED_DATA  0x0002

/*
 * FLAG_PREV_CABINET is set if the cabinet file is not the first in a set
 * of cabinet files. When this bit is set, the szCabinetPrev and szDiskPrev
 * fields are present in this CFHEADER.
 */
#define FLAG_PREV_CABINET 0x0001
/*
 * FLAG_NEXT_CABINET is set if the cabinet file is not the last in a set of
 * cabinet files. When this bit is set, the szCabinetNext and szDiskNext
* fields are present in this CFHEADER.
*/
#define FLAG_NEXT_CABINET 0x0002
/*
 * FLAG_RESERVE_PRESENT is set if the cabinet file contains any reserved
 * fields. When this bit is set, the cbCFHeader, cbCFFolder, and cbCFData
 * fields are present in this CFHEADER.
 */
#define FLAG_RESERVE_PRESENT 0x0004




typedef unsigned char u_char;


/*
 * ASN.1 definitions (more or less from official MS Authenticode docs)
 */
typedef struct {
    int type;
    union {
        ASN1_BMPSTRING *unicode;
        ASN1_IA5STRING *ascii;
    } value;
} SpcString;

DECLARE_ASN1_FUNCTIONS(SpcString)

typedef struct {
    ASN1_OCTET_STRING *classId;
    ASN1_OCTET_STRING *serializedData;
} SpcSerializedObject;

DECLARE_ASN1_FUNCTIONS(SpcSerializedObject)

typedef struct {
    int type;
    union {
        ASN1_IA5STRING *url;
        SpcSerializedObject *moniker;
        SpcString *file;
    } value;
} SpcLink;

DECLARE_ASN1_FUNCTIONS(SpcLink)

typedef struct {
    SpcString *programName;
    SpcLink   *moreInfo;
} SpcSpOpusInfo;

DECLARE_ASN1_FUNCTIONS(SpcSpOpusInfo)


typedef struct {
    ASN1_OBJECT *type;
    ASN1_TYPE *value;
} SpcAttributeTypeAndOptionalValue;

DECLARE_ASN1_FUNCTIONS(SpcAttributeTypeAndOptionalValue)

typedef struct {
    ASN1_OBJECT *algorithm;
    ASN1_TYPE *parameters;
} AlgorithmIdentifier;

DECLARE_ASN1_FUNCTIONS(AlgorithmIdentifier)

typedef struct {
    AlgorithmIdentifier *digestAlgorithm;
    ASN1_OCTET_STRING *digest;
} DigestInfo;

DECLARE_ASN1_FUNCTIONS(DigestInfo)

typedef struct {
    SpcAttributeTypeAndOptionalValue *data;
    DigestInfo *messageDigest;
} SpcIndirectDataContent;

DECLARE_ASN1_FUNCTIONS(SpcIndirectDataContent)


typedef struct {
    char const* infile;
    char const* outfile;
    EVP_PKEY* pkey;
    X509* cert;
    STACK_OF(X509)* certs;
} GLOBAL_OPTIONS;




class CabFileController
{
private:
    typedef unsigned char u_char;

    size_t file_size;
    BIO* hash;
    BIO* outdata;
    EVP_MD const* md;
    char* indata;
    
public:
    CabFileController(GLOBAL_OPTIONS& options);
    ~CabFileController();
    int get_hash_size();
    EVP_MD const* get_md() const;
    int process_header();
    PKCS7* pkcs7_signature_new(GLOBAL_OPTIONS& options);
    int append_pkcs7(PKCS7* p7);
    void update_data_size(PKCS7* p7);
    ASN1_OBJECT* spc_indirect_data_attributetypeandoptionalvalue_get(u_char** p, int* len);
};
