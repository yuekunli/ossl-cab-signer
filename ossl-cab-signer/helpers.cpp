#include "osslsigncode.h"
#include "helpers.h"
#include<string>
#include<iostream>
#include<fstream>

/*
 * [in] infile
 * [returns] file size
 */
uint32_t get_file_size(const char *infile)
{
    int ret;
#ifdef _WIN32
    struct _stat64 st;
    ret = _stat64(infile, &st);
#else
    struct stat st;
    ret = stat(infile, &st);
#endif
    if (ret) {
        fprintf(stderr, "Failed to open file: %s\n", infile);
        return 0;
    }

    if (st.st_size < 4) {
        fprintf(stderr, "Unrecognized file type - file is too short: %s\n", infile);
        return 0;
    }
    if (st.st_size > UINT32_MAX) {
        fprintf(stderr, "Unsupported file - too large: %s\n", infile);
        return 0;
    }
    return (uint32_t)st.st_size;
}

/*
 * [in] infile: starting address for the new mapping
 * [returns] pointer to the mapped area
 */
char *map_file(const char *infile, const size_t size)
{
    char *indata = NULL;
    HANDLE fhandle, fmap;
    (void)size;
    fhandle = CreateFileA(infile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (fhandle == INVALID_HANDLE_VALUE) {
        return NULL;
    }
    fmap = CreateFileMapping(fhandle, NULL, PAGE_READONLY, 0, 0, NULL);
    CloseHandle(fhandle);
    if (fmap == NULL) {
        return NULL;
    }
    indata = (char *)MapViewOfFile(fmap, FILE_MAP_READ, 0, 0, 0);
    CloseHandle(fmap);

    return indata;
}

/*
 * [in] indata: starting address space
 * [in] size: mapped area length
 * [returns] none
 */
void unmap_file(char *indata)
{
    if (!indata)
        return;

    UnmapViewOfFile(indata);

}

char* read_binary_into_buffer(char const* file_path, size_t* _size)
{
    std::ifstream pkcs12_file_stream(file_path, std::ios::binary | std::ios::ate);
    std::streamsize size = pkcs12_file_stream.tellg();
    pkcs12_file_stream.seekg(0, std::ios::beg);
    char* p = (char*)OPENSSL_malloc(size);
    pkcs12_file_stream.read(p, size);
    *_size = size;
    return p;
}



/*
 * PE and CAB format specific
 * [in] none
 * [returns] pointer to SpcLink
 */
SpcLink* spc_link_obsolete_get(void)
{
    // Unicode string of "<<<Obsolete>>>", but it doesn't say in what encoding.
    // just use the values of code points, each code point is at least 4 hex digits.
    const u_char obsolete[] = {
        0x00, 0x3c, 0x00, 0x3c, 0x00, 0x3c, 0x00, 0x4f,
        0x00, 0x62, 0x00, 0x73, 0x00, 0x6f, 0x00, 0x6c,
        0x00, 0x65, 0x00, 0x74, 0x00, 0x65, 0x00, 0x3e,
        0x00, 0x3e, 0x00, 0x3e
    };
    SpcLink* link = SpcLink_new();
    link->type = 2;
    link->value.file = SpcString_new();
    link->value.file->type = 0;
    link->value.file->value.unicode = ASN1_BMPSTRING_new();
    ASN1_STRING_set(link->value.file->value.unicode, obsolete, sizeof(obsolete));
    return link;
}


/*
 * [in] ctx: FILE_FORMAT_CTX structure
 * [returns] pointer to SpcSpOpusInfo structure
 */
static SpcSpOpusInfo* spc_sp_opus_info_create()
{
    SpcSpOpusInfo* info = SpcSpOpusInfo_new();

    /*
    if (ctx->options->desc) {
        info->programName = SpcString_new();
        info->programName->type = 1;
        info->programName->value.ascii = ASN1_IA5STRING_new();
        ASN1_STRING_set((ASN1_STRING *)info->programName->value.ascii,
                ctx->options->desc, (int)strlen(ctx->options->desc));
    }
    if (ctx->options->url) {
        info->moreInfo = SpcLink_new();
        info->moreInfo->type = 0;
        info->moreInfo->value.url = ASN1_IA5STRING_new();
        ASN1_STRING_set((ASN1_STRING *)info->moreInfo->value.url,
                ctx->options->url, (int)strlen(ctx->options->url));
    }
    */
    return info;
}

/*
 * [in, out] si: PKCS7_SIGNER_INFO structure
 * [in] ctx: FILE_FORMAT_CTX structure
 * [returns] 0 on error or 1 on success
 */
static int pkcs7_signer_info_add_signed_attribute_opus(PKCS7_SIGNER_INFO* si)
{
    SpcSpOpusInfo* opus;
    ASN1_STRING* astr;
    int len;
    u_char* p = NULL;

    opus = spc_sp_opus_info_create();
    if ((len = i2d_SpcSpOpusInfo(opus, NULL)) <= 0
        || (p = (u_char*)OPENSSL_malloc((size_t)len)) == NULL) {
        SpcSpOpusInfo_free(opus);
        return 0; /* FAILED */
    }
    i2d_SpcSpOpusInfo(opus, &p);
    p -= len;
    astr = ASN1_STRING_new();
    ASN1_STRING_set(astr, p, len);
    OPENSSL_free(p);
    SpcSpOpusInfo_free(opus);
    return PKCS7_add_signed_attribute(si, OBJ_txt2nid(SPC_SP_OPUS_INFO_OBJID), V_ASN1_SEQUENCE, astr);
}

/*
 * PE, MSI, CAB and APPX file specific
 * Add "1.3.6.1.4.1.311.2.1.4" SPC_INDIRECT_DATA_OBJID signed attribute
 * [in, out] p7: new PKCS#7 signature
 * [returns] 0 on error or 1 on success
 */
int pkcs7_signer_info_add_signed_attribute_content_type(PKCS7* p7)
{
    STACK_OF(PKCS7_SIGNER_INFO)* signer_info;
    PKCS7_SIGNER_INFO* si;

    signer_info = PKCS7_get_signer_info(p7);
    if (!signer_info)
        return 0; /* FAILED */
    si = sk_PKCS7_SIGNER_INFO_value(signer_info, 0);
    if (!si)
        return 0; /* FAILED */
    if (!PKCS7_add_signed_attribute(si, NID_pkcs9_contentType,
        V_ASN1_OBJECT, OBJ_txt2obj(SPC_INDIRECT_DATA_OBJID, 1)))
        return 0; /* FAILED */
    return 1; /* OK */
}


/*
 * [in, out] si: PKCS7_SIGNER_INFO structure
 * [in] ctx: structure holds input and output data
 * [returns] 0 on error or 1 on success
 */
static int pkcs7_signer_info_add_signed_attribute_purpose(PKCS7_SIGNER_INFO* si)
{
    static const u_char purpose_ind[] = {
        0x30, 0x0c, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04,
        0x01, 0x82, 0x37, 0x02, 0x01, 0x15
    };
    static const u_char purpose_comm[] = {
        0x30, 0x0c, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04,
        0x01, 0x82, 0x37, 0x02, 0x01, 0x16
    };
    ASN1_STRING* purpose = ASN1_STRING_new();


    ASN1_STRING_set(purpose, purpose_ind, sizeof purpose_ind);

    return PKCS7_add_signed_attribute(si, OBJ_txt2nid(SPC_STATEMENT_TYPE_OBJID),
        V_ASN1_SEQUENCE, purpose);
}



/*
 * Allocate, set type, add content and return a new PKCS#7 signature
 * [in] ctx: structure holds input and output data
 * [returns] pointer to PKCS#7 structure
 */
PKCS7 *pkcs7_create(GLOBAL_OPTIONS&options, EVP_MD const* md)
{
    int i, signer = -1;
    PKCS7 *p7;
    PKCS7_SIGNER_INFO *si = NULL;
    STACK_OF(X509) *chain = NULL;

    p7 = PKCS7_new();
    PKCS7_set_type(p7, NID_pkcs7_signed);
    PKCS7_content_new(p7, NID_pkcs7_data);
    if (options.cert != NULL) {
        /*
         * the private key and corresponding certificate are parsed from the PKCS12
         * structure or loaded from the security token, so we may omit to check
         * the consistency of a private key with the public key in an X509 certificate
         */
        si = PKCS7_add_signature(p7, options.cert, options.pkey, md);
        if (si == NULL)
            return NULL; /* FAILED */
    } else {
        /* find the signer's certificate located somewhere in the whole certificate chain */
        for (i=0; i<sk_X509_num(options.certs); i++) {
            X509 *signcert = sk_X509_value(options.certs, i);
            if (X509_check_private_key(signcert, options.pkey)) {
                si = PKCS7_add_signature(p7, signcert, options.pkey, md);
                signer = i;
                break;
            }
        }
        if (si == NULL) {
            
            return NULL; /* FAILED */
        }
    }
    
    if (!pkcs7_signer_info_add_signed_attribute_purpose(si)) {
        return NULL; /* FAILED */
    }
    if (!pkcs7_signer_info_add_signed_attribute_opus(si)) {
        fprintf(stderr, "Couldn't allocate memory for opus info\n");
        return NULL; /* FAILED */
    }
    
    /* create X509 chain sorted in ascending order by their DER encoding */
    chain = X509_chain_get_sorted(options, signer);
    if (chain == NULL) {
        fprintf(stderr, "Failed to create a sorted certificate chain\n");
        return NULL; /* FAILED */
    }
    /* add sorted certificate chain */
    for (i=0; i<sk_X509_num(chain); i++) {
        PKCS7_add_certificate(p7, sk_X509_value(chain, i));
    }
    
    sk_X509_free(chain);
    return p7; /* OK */
}









/*
 * [out] blob: SpcIndirectDataContent data
 * [out] len: SpcIndirectDataContent data length
 * [in] ctx: FILE_FORMAT_CTX structure
 * [returns] 0 on error or 1 on success
 */
static int spc_indirect_data_content_create_with_hash_placeholder(u_char** blob, int* len, CabFileController& cab)
{
    u_char* p = NULL;
    int mdtype, hashlen, l = 0;
    u_char* hash;
    SpcIndirectDataContent* idc = SpcIndirectDataContent_new();


    mdtype = EVP_MD_nid(cab.get_md());

    idc->data->value = ASN1_TYPE_new();
    idc->data->value->type = V_ASN1_SEQUENCE;
    idc->data->value->value.sequence = ASN1_STRING_new();
    idc->data->type = cab.spc_indirect_data_attributetypeandoptionalvalue_get(&p, &l);
    idc->data->value->value.sequence->data = p;
    idc->data->value->value.sequence->length = l;
    idc->messageDigest->digestAlgorithm->algorithm = OBJ_nid2obj(mdtype);
    idc->messageDigest->digestAlgorithm->parameters = ASN1_TYPE_new();
    idc->messageDigest->digestAlgorithm->parameters->type = V_ASN1_NULL;

    hashlen = cab.get_hash_size();
    hash = (u_char*)OPENSSL_zalloc((size_t)hashlen);
    ASN1_OCTET_STRING_set(idc->messageDigest->digest, hash, hashlen);
    // The hash inside this SpcIndirectDataContent is all zero for now.

    OPENSSL_free(hash);

    *len = i2d_SpcIndirectDataContent(idc, NULL);
    *blob = (u_char*)OPENSSL_malloc((size_t)*len);
    p = *blob;
    i2d_SpcIndirectDataContent(idc, &p);
    SpcIndirectDataContent_free(idc);
    *len -= hashlen;  // make "len" point at the starting of the hash part inside this DER string
    return 1; /* OK */
}






/*
 * Return spcIndirectDataContent.
 * [in] hash: message digest BIO
 * [in] ctx: structure holds input and output data
 * [returns] content
 */
ASN1_OCTET_STRING *spc_indirect_data_content_create(BIO *hash, CabFileController& cab)
{
    ASN1_OCTET_STRING *content;
    u_char mdbuf[5 * EVP_MAX_MD_SIZE + 24];
    int mdlen, hashlen, len = 0;
    u_char *data, *p = NULL;

    content = ASN1_OCTET_STRING_new();
    if (!content) {
        return NULL; /* FAILED */
    }
    if (!spc_indirect_data_content_create_with_hash_placeholder(&p, &len, cab)) {
        ASN1_OCTET_STRING_free(content);
        return NULL; /* FAILED */
    }
    hashlen = cab.get_hash_size();
    if (hashlen > EVP_MAX_MD_SIZE) {
        /* APPX format specific */
        mdlen = BIO_read(hash, (char*)mdbuf, hashlen);
    } else {
        mdlen = BIO_gets(hash, (char*)mdbuf, EVP_MAX_MD_SIZE);
    }
    data = (u_char*)OPENSSL_malloc((size_t)(len + mdlen));
    memcpy(data, p, (size_t)len);
    OPENSSL_free(p);
    memcpy(data + len, mdbuf, (size_t)mdlen);
    if (!ASN1_OCTET_STRING_set(content, data, len + mdlen)) {
        ASN1_OCTET_STRING_free(content);
        OPENSSL_free(data);
        return NULL; /* FAILED */
    }
    OPENSSL_free(data);
    return content;
}





/*
 * Signs the data and place the signature in p7
 * [in, out] p7: new PKCS#7 signature
 * [in] data: content data
 * [in] len: content length
 */
int pkcs7_sign_content(PKCS7 *p7, const u_char *data, int len)
{
    BIO *p7bio;

    if ((p7bio = PKCS7_dataInit(p7, NULL)) == NULL) {
        fprintf(stderr, "PKCS7_dataInit failed\n");
        return 0; /* FAILED */
    }
    BIO_write(p7bio, data, len);
    (void)BIO_flush(p7bio);
    if (!PKCS7_dataFinal(p7, p7bio)) {
        fprintf(stderr, "PKCS7_dataFinal failed\n");
        BIO_free_all(p7bio);
        return 0; /* FAILED */
    }
    BIO_free_all(p7bio);
    return 1; /* OK */
}





/*
 * PE, MSI, CAB and APPX format specific
 * Sign the MS Authenticode spcIndirectDataContent blob.
 * The spcIndirectDataContent structure is used in Authenticode signatures
 * to store the digest and other attributes of the signed file.
 * [in, out] p7: new PKCS#7 signature
 * [in] content: spcIndirectDataContent
 * [returns] 0 on error or 1 on success
 */
int sign_spc_indirect_data_content(PKCS7* p7, ASN1_OCTET_STRING* content)
{
    int len, inf, tag, tagClass;
    long plen;
    const u_char* data, * p;
    PKCS7* td7;

    p = data = ASN1_STRING_get0_data(content);
    len = ASN1_STRING_length(content);
    inf = ASN1_get_object(&p, &plen, &tag, &tagClass, len);
    if (inf != V_ASN1_CONSTRUCTED || tag != V_ASN1_SEQUENCE
        || !pkcs7_sign_content(p7, p, (int)plen)) {
        fprintf(stderr, "Failed to sign spcIndirectDataContent\n");
        return 0; /* FAILED */
    }
    td7 = PKCS7_new();
    if (!td7) {
        fprintf(stderr, "PKCS7_new failed\n");
        return 0; /* FAILED */
    }
    td7->type = OBJ_txt2obj(SPC_INDIRECT_DATA_OBJID, 1);
    td7->d.other = ASN1_TYPE_new();
    td7->d.other->type = V_ASN1_SEQUENCE;
    td7->d.other->value.sequence = ASN1_STRING_new();
    ASN1_STRING_set(td7->d.other->value.sequence, data, len);
    if (!PKCS7_set_content(p7, td7)) {
        fprintf(stderr, "PKCS7_set_content failed\n");
        PKCS7_free(td7);
        return 0; /* FAILED */
    }
    return 1; /* OK */
}











static int X509_compare(const X509* const* a, const X509* const* b);

/*
 * Create certificate chain sorted in ascending order by their DER encoding.
 * [in] ctx: structure holds input and output data
 * [in] signer: signer's certificate number in the certificate chain
 * [returns] sorted certificate chain
 */
static STACK_OF(X509) *X509_chain_get_sorted(GLOBAL_OPTIONS&options, int signer)
{
    int i;
    STACK_OF(X509) *chain = sk_X509_new(X509_compare);

    /* add the signer's certificate */
    if (options.cert != NULL && !sk_X509_push(chain, options.cert)) {
        sk_X509_free(chain);
        return NULL;
    }
    if (signer != -1 && !sk_X509_push(chain, sk_X509_value(options.certs, signer))) {
        sk_X509_free(chain);
        return NULL;
    }
    /* add the certificate chain */
    for (i=0; i<sk_X509_num(options.certs); i++) {
        if (i == signer)
            continue;
        if (!sk_X509_push(chain, sk_X509_value(options.certs, i))) {
            sk_X509_free(chain);
            return NULL;
        }
    }
    
    /* sort certificate chain using the supplied comparison function */
    sk_X509_sort(chain);
    return chain;
}

/*
 * X.690-compliant certificate comparison function
 * Windows requires catalog files to use PKCS#7
 * content ordering specified in X.690 section 11.6
 * https://support.microsoft.com/en-us/topic/october-13-2020-kb4580358-security-only-update-d3f6eb3c-d7c4-a9cb-0de6-759386bf7113
 * This algorithm is different from X509_cmp()
 * [in] a_ptr, b_ptr: pointers to X509 certificates
 * [returns] certificates order
 */
static int X509_compare(const X509 *const *a, const X509 *const *b)
{
    u_char *a_data, *b_data;
    size_t a_len, b_len;
    int ret;

    a_len = (size_t)i2d_X509(*a, NULL);
    a_data = (u_char*)OPENSSL_malloc(a_len);
    i2d_X509(*a, &a_data);

    b_len = (size_t)i2d_X509(*b, NULL);
    b_data = (u_char*)OPENSSL_malloc(b_len);
    i2d_X509(*b, &b_data);

    ret = memcmp(a_data, b_data, min(a_len, b_len));
    OPENSSL_free(a_data);
    OPENSSL_free(b_data);

    if (ret == 0 && a_len != b_len) /* identical up to the length of the shorter DER */
        ret = a_len < b_len ? -1 : 1; /* shorter is smaller */
    return ret;
}