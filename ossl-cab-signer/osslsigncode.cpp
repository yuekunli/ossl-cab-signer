#include<string>
#include<iostream>
#include<fstream>

#include "osslsigncode.h"
#include "helpers.h"
#include "CabFileSigner.h"

#include <openssl/asn1t.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pkcs7.h>
#include <openssl/pkcs12.h>
#include <openssl/safestack.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h> /* X509_PURPOSE */


/*
 * $ echo -n 300c060a2b060104018237020115 | xxd -r -p | openssl asn1parse -i -inform der
 * 0:d=0  hl=2 l=  12 cons: SEQUENCE
 * 2:d=1  hl=2 l=  10 prim:  OBJECT     :Microsoft Individual Code Signing
*/
const u_char purpose_ind[] = {
    0x30, 0x0c, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04,
    0x01, 0x82, 0x37, 0x02, 0x01, 0x15
};

/*
 * $ echo -n 300c060a2b060104018237020116 | xxd -r -p | openssl asn1parse -i -inform der
 * 0:d=0  hl=2 l=  12 cons: SEQUENCE
 * 2:d=1  hl=2 l=  10 prim:  OBJECT     :Microsoft Commercial Code Signing
*/
const u_char purpose_comm[] = {
    0x30, 0x0c, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04,
    0x01, 0x82, 0x37, 0x02, 0x01, 0x16
};

/*
 * ASN.1 definitions (more or less from official MS Authenticode docs)
 */
ASN1_CHOICE(SpcString) = {
    ASN1_IMP_OPT(SpcString, value.unicode, ASN1_BMPSTRING, 0),
    ASN1_IMP_OPT(SpcString, value.ascii, ASN1_IA5STRING, 1)
} ASN1_CHOICE_END(SpcString)

IMPLEMENT_ASN1_FUNCTIONS(SpcString)

ASN1_SEQUENCE(SpcSerializedObject) = {
    ASN1_SIMPLE(SpcSerializedObject, classId, ASN1_OCTET_STRING),
    ASN1_SIMPLE(SpcSerializedObject, serializedData, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(SpcSerializedObject)

IMPLEMENT_ASN1_FUNCTIONS(SpcSerializedObject)

ASN1_CHOICE(SpcLink) = {
    ASN1_IMP_OPT(SpcLink, value.url, ASN1_IA5STRING, 0),
    ASN1_IMP_OPT(SpcLink, value.moniker, SpcSerializedObject, 1),
    ASN1_EXP_OPT(SpcLink, value.file, SpcString, 2)
} ASN1_CHOICE_END(SpcLink)

IMPLEMENT_ASN1_FUNCTIONS(SpcLink)

ASN1_SEQUENCE(SpcSpOpusInfo) = {
    ASN1_EXP_OPT(SpcSpOpusInfo, programName, SpcString, 0),
    ASN1_EXP_OPT(SpcSpOpusInfo, moreInfo, SpcLink, 1)
} ASN1_SEQUENCE_END(SpcSpOpusInfo)

IMPLEMENT_ASN1_FUNCTIONS(SpcSpOpusInfo)


ASN1_SEQUENCE(SpcAttributeTypeAndOptionalValue) = {
    ASN1_SIMPLE(SpcAttributeTypeAndOptionalValue, type, ASN1_OBJECT),
    ASN1_EXP_OPT(SpcAttributeTypeAndOptionalValue, value, ASN1_ANY, 0)
} ASN1_SEQUENCE_END(SpcAttributeTypeAndOptionalValue)

IMPLEMENT_ASN1_FUNCTIONS(SpcAttributeTypeAndOptionalValue)

ASN1_SEQUENCE(AlgorithmIdentifier) = {
    ASN1_SIMPLE(AlgorithmIdentifier, algorithm, ASN1_OBJECT),
    ASN1_OPT(AlgorithmIdentifier, parameters, ASN1_ANY)
} ASN1_SEQUENCE_END(AlgorithmIdentifier)

IMPLEMENT_ASN1_FUNCTIONS(AlgorithmIdentifier)

ASN1_SEQUENCE(DigestInfo) = {
    ASN1_SIMPLE(DigestInfo, digestAlgorithm, AlgorithmIdentifier),
    ASN1_SIMPLE(DigestInfo, digest, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(DigestInfo)

IMPLEMENT_ASN1_FUNCTIONS(DigestInfo)

ASN1_SEQUENCE(SpcIndirectDataContent) = {
    ASN1_SIMPLE(SpcIndirectDataContent, data, SpcAttributeTypeAndOptionalValue),
    ASN1_SIMPLE(SpcIndirectDataContent, messageDigest, DigestInfo)
} ASN1_SEQUENCE_END(SpcIndirectDataContent)

IMPLEMENT_ASN1_FUNCTIONS(SpcIndirectDataContent)


// An example of these macros (IMPLEMENT_ASN1_FUNCTIONS, ANS1_SEQUENCE, etc)
// and that corresponding one in osslsigncode.h (DECLARE_ASN1_FUNCTIONS) is here:
// https://docs.openssl.org/3.0/man3/ASN1_item_sign/#return-values


/*
 * [in, out] options: structure holds the input data
 * [returns] none
 */
static void free_options(SigningCryptoParams *options)
{
    /* If key is NULL nothing is done */
    EVP_PKEY_free(options->pkey);
    options->pkey = NULL;
    /* If X509 structure is NULL nothing is done */
    X509_free(options->cert);
    options->cert = NULL;
    /* Free up all elements of sk structure and sk itself */
    sk_X509_pop_free(options->certs, X509_free);
    options->certs = NULL;
}


SigningCryptoParams::SigningCryptoParams()
    : pkey(NULL),
    cert(NULL),
    certs(NULL)
{}

SigningCryptoParams::~SigningCryptoParams()
{
    if (pkey != nullptr)
    {
        EVP_PKEY_free(pkey);
        pkey = nullptr;
    }

    if (cert != nullptr)
    {
        X509_free(cert);
        cert = nullptr;
    }

    if (certs != nullptr)
    {
        sk_X509_pop_free(certs, X509_free);
        certs = nullptr;
    }
}


int enter(
    char const* input_cab_file_path, 
    char const* output_file_path, 
    char const* pkcs12_file_path, 
    char const* password, 
    int password_length)
{
    SigningCryptoParams cryptoParams;
    PKCS7 *p7 = NULL;
    int ret = -1;

    OSSL_LIB_CTX_load_config(NULL, "C:\\ws\\openssl-3.2.1_output\\static_64_debug\\openssl_default.cnf");

    /* create some MS Authenticode OIDS we need later on,
    * but need to look them up first, in case this program is used as a library,
    * and this code is invoked repeatedly, those OIDs would have been created after first invocation
    */
    
    ASN1_OBJECT* tmp_oid = OBJ_txt2obj(SPC_STATEMENT_TYPE_OBJID, 1);
    if (OBJ_obj2nid(tmp_oid) == NID_undef)
    {
        ret = OBJ_create(SPC_STATEMENT_TYPE_OBJID, NULL, NULL);
        if (ret == 0)
        {
            return 0;
        }
    }

    tmp_oid = OBJ_txt2obj(SPC_SP_OPUS_INFO_OBJID, 1);
    if (OBJ_obj2nid(tmp_oid) == NID_undef)
    {
        ret = OBJ_create(SPC_SP_OPUS_INFO_OBJID, NULL, NULL);
        if (ret == 0)
        {
            return 0;
        }
    }

    /* read key and certificates */
    if (!read_pkcs12(cryptoParams, pkcs12_file_path, password, password_length))
        return 1;

    CabFileSigner cab{ };
    ret = cab.init(input_cab_file_path, output_file_path);
    if (ret != 1)
    {
        return ret;
    }
   
    ret = cab.sign(cryptoParams);

    printf(ret ? "Succeeded\n" : "Failed\n");

    return ret;
}

// this is almost same as "enter", this function takes pkcs12 encoded cert in a buffer
int enter2(
    char const* input_cab_file_path,
    char const* output_file_path,
    char const* pkcs12_content_buf,
    int pkcs12_buf_len,
    char const* password,
    int password_length)
{
    SigningCryptoParams cryptoParams;
    PKCS7* p7 = NULL;
    int ret = -1;

    OSSL_LIB_CTX_load_config(NULL, "C:\\ws\\openssl-3.2.1_output\\static_64_debug\\openssl_default.cnf");

    /* create some MS Authenticode OIDS we need later on,
    * but need to look them up first, in case this program is used as a library,
    * and this code is invoked repeatedly, those OIDs would have been created after first invocation
    */

    ASN1_OBJECT* tmp_oid = OBJ_txt2obj(SPC_STATEMENT_TYPE_OBJID, 1);
    if (OBJ_obj2nid(tmp_oid) == NID_undef)
    {
        ret = OBJ_create(SPC_STATEMENT_TYPE_OBJID, NULL, NULL);
        if (ret == 0)
        {
            return 0;
        }
    }

    tmp_oid = OBJ_txt2obj(SPC_SP_OPUS_INFO_OBJID, 1);
    if (OBJ_obj2nid(tmp_oid) == NID_undef)
    {
        ret = OBJ_create(SPC_SP_OPUS_INFO_OBJID, NULL, NULL);
        if (ret == 0)
        {
            return 0;
        }
    }

    /* read key and certificates */
    if (!read_pkcs12(cryptoParams, pkcs12_content_buf, pkcs12_buf_len, password, password_length))
        return 1;

    CabFileSigner cab{ };
    ret = cab.init(input_cab_file_path, output_file_path);
    if (ret != 1)
    {
        return ret;
    }

    ret = cab.sign(cryptoParams);

    printf(ret ? "Succeeded\n" : "Failed\n");

    return ret;
}


// Every function (except main) in this project uses '1' to indicate success, '0' to indicate failure.
int main(int argc, char** argv)
{
    int ret = enter(argv[1]/*input file path*/, argv[2]/*output file path*/, argv[3]/*pkcs12 file path*/, NULL/*password*/, 0/*password length*/);

    return ret == 1? 0 : ret;
}


extern "C" {
    __declspec(dllexport) int signCabFile(char const* input_cab_file_path,
        char const* output_file_path,
        char const* pkcs12_file_path,
        char const* password,
        int password_length)
    {
       return enter(input_cab_file_path, output_file_path, pkcs12_file_path, password, password_length);
    }

    __declspec(dllexport) int signCabFile2(char const* input_cab_file_path,
        char const* output_file_path,
        char const* pkcs12_content_buf,
        int pkcs12_buf_len,
        char const* password,
        int password_length)
    {
        return enter2(input_cab_file_path, output_file_path, pkcs12_content_buf, pkcs12_buf_len, password, password_length);
    }
}