#include<string>
#include<iostream>
#include<fstream>
#include "osslsigncode.h"
#include "helpers.h"

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


char* read_binary_into_buffer(char const* file_path, size_t* _size);

/*
 * [in, out] options: structure holds the input data
 * [returns] none
 */
static void free_options(GLOBAL_OPTIONS *options)
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


/*
 * [in, out] options: structure holds the input data
 * [returns] 0 on error or 1 on success
 */
static int read_crypto_params(GLOBAL_OPTIONS* options, char const* pkcs12_file_path, char const* password, int password_length)
{
    int ret = 0;
    BIO* btmp;
    PKCS12* p12;

    bool test_buffer = false;

    if (test_buffer)
    {
        size_t pkcs12_size;
        char* pkcs12_buffer = read_binary_into_buffer(pkcs12_file_path, &pkcs12_size);
        btmp = BIO_new_mem_buf(pkcs12_buffer, pkcs12_size);
    }
    else
    {
        btmp = BIO_new_file(pkcs12_file_path, "rb");
    }
    
    if (!btmp) {
        fprintf(stderr, "Failed to read PKCS#12\n");
        return 0; /* FAILED */
    }
    p12 = d2i_PKCS12_bio(btmp, NULL);
    if (!p12) {
        fprintf(stderr, "Failed to extract PKCS#12 data\n");
        goto out; /* FAILED */
    }
    if (!PKCS12_parse(p12, password_length > 0 ? password : "", &options->pkey, &options->cert, &options->certs)) {
        fprintf(stderr, "Failed to parse PKCS#12\n");
        PKCS12_free(p12);
        goto out; /* FAILED */
    }
    PKCS12_free(p12);
    
    ret = 1; /* OK */
out:
    BIO_free(btmp);

    return ret;
}


int enter(char const* input_cab_file_path, char const* output_file_path, char const* pkcs12_file_path, char const* password, int password_length)
{

    GLOBAL_OPTIONS options;
    PKCS7 *p7 = NULL;
    BIO *outdata = NULL;
    BIO *hash = NULL;
    int ret = -1;

    /* reset options */
    memset(&options, 0, sizeof(GLOBAL_OPTIONS));
    options.infile = input_cab_file_path;
    options.outfile = output_file_path;
    /* create some MS Authenticode OIDS we need later on */
    if (!OBJ_create(SPC_STATEMENT_TYPE_OBJID, NULL, NULL)
        || !OBJ_create(SPC_SP_OPUS_INFO_OBJID, NULL, NULL))
        return 1;


    

    /* read key and certificates */
    if (!read_crypto_params(&options, pkcs12_file_path, password, password_length))
        return 1;


    /* Create message digest BIO */

    CabFileController cab{ options };
   
    if (!cab.process_header()) {
        return 1;
    }
    
    
    p7 = cab.pkcs7_signature_new(options);
    if (!p7) {
        return 1;
    }
    

   
    
    ret = cab.append_pkcs7(p7);
    if (ret) {
        PKCS7_free(p7);
        return 1;
    }
    
    
    cab.update_data_size(p7);
    
    PKCS7_free(p7);

    

    if (options.outfile) {
        /* unlink outfile */
        remove_file(options.outfile);
    }

   printf(ret ? "Failed\n" : "Succeeded\n");

    return ret;
}
/*
char* read_binary_into_buffer(char const* file_path, size_t *_size)
{
    std::ifstream pkcs12_file_stream(file_path, std::ios::binary | std::ios::ate);
    std::streamsize size = pkcs12_file_stream.tellg();
    pkcs12_file_stream.seekg(0, std::ios::beg);
    char* p = (char*)OPENSSL_malloc(size);
    pkcs12_file_stream.read(p, size);
    *_size = size;
    return p;
}
*/

int main(int argc, char** argv)
{
    int ret = enter(argv[1], argv[2], argv[3], NULL, 0);

    return ret;
}
