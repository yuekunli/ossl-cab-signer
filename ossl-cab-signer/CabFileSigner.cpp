#include "helpers.h"
#include "osslsigncode.h"

#include "CabFileSigner.h"

#include<stdexcept>
#include<algorithm>

#include<openssl/core_names.h>

typedef unsigned char u_char;

namespace {
    size_t file_size(BIO* bio)
    {
        FILE* fp = nullptr;
        long original_pos = -1L;
        long size_temp = -1L;
        long long file_size = -1L;

        //verify this is a file first
        if (BIO_method_type(bio) != BIO_TYPE_FILE)
            return 0;

        if (BIO_get_fp(bio, &fp) <= 0 || fp == nullptr)
            return 0;

        // save original position
        original_pos = ftell(fp);
        if (original_pos == -1LL)
            return 0;

        // seek to end
        if (fseek(fp, 0, SEEK_END) != 0)
        {
            fseek(fp, original_pos, SEEK_SET);
            return 0;
        }

        //get size
        size_temp = ftell(fp);
        if (size_temp == -1L)
        {
            fseek(fp, original_pos, SEEK_SET);
            return 0;
        }

        fseek(fp, original_pos, SEEK_SET);
        return static_cast<size_t>(size_temp);
    }
}


CabFileSigner::CabFileSigner()
    :indata_bio(nullptr),
    original_cab_file_size(0),
    hash(nullptr),
    outdata(nullptr),
    md(nullptr),
    //indata(nullptr),
    p7(nullptr),
    errorCode(ErrorCode::OK),
    output_file_path(nullptr)
{
}


/*
 * Allocate and return a CAB file format context.
 * [in, out] options: structure holds the input data
 * [out] hash: message digest BIO
 * [in] outdata: outdata file BIO
 * [returns] pointer to CAB file format context
 */
CabFileSigner::CabFileSigner(char const* infile, char const* outfile)
    :indata_bio(nullptr),
    original_cab_file_size(0),
    hash(nullptr),
    outdata(nullptr),
    md(nullptr),
    //indata(nullptr),
    p7(nullptr),
    errorCode(ErrorCode::OK),
    output_file_path(nullptr)
{
    int ret = init(infile, outfile);
    if (ret != 1)
    {
        throw std::runtime_error("Fail to initialize");
    }
}


bool CabFileSigner::read_exact(size_t offset, void* buf, size_t len)
{
    // BIO_seek is a macro and it expands to BIO_ctrl(indata_bio, 128, offset, 0)
    // the 3rd argument is should be a "long" type integer, yet the "offset" here is size_t
    // on 64-bit machine, size_t will be 64 bit long, and "long" integer type is maybe 32-bit?
    // the upper limit of 32-bit signed integer is ~2GB.
    // What if the underlying file is bigger than 2GB and I want to seek over 2GB?
    // 32-bit system has file size limit of 2GB, so I can have a file bigger than 2GB anyway on
    // 32-bit system, so this is fine on 32-bit system.
    // but on 64-bit system, this depends on why "long" type is implemented with 32bit or 64 bit
    // and whether "size_t" is implemented as 32bit or 64 bit?
    // It looks like on 64-bit Windows, "long" is 32 bit and "size_t" is 64 bit.
    // https://stackoverflow.com/questions/384502/what-is-the-bit-size-of-long-on-64-bit-windows
    if (BIO_seek(indata_bio, offset) != 0)
    {
        errorCode = ErrorCode::INPUT_FILE_IO_ERROR;
        return false;
    }

    size_t bytes_read_total = 0;
    if (!BIO_read_ex(indata_bio, buf, len, &bytes_read_total))
    {
        if (BIO_eof(indata_bio) <= 0)
        {
            errorCode = ErrorCode::INPUT_FILE_IO_ERROR;
            return false;
        }

        if (bytes_read_total != len)
        {
            errorCode = ErrorCode::INPUT_FILE_IO_ERROR;
            return false;
        }
    }

    if (bytes_read_total != len)
    {
        errorCode = ErrorCode::INPUT_FILE_IO_ERROR;
        return false;
    }
    return true;
}


int CabFileSigner::init(char const* infile, char const* outfile)
{
    indata_bio = BIO_new_file(infile, "rb");
    if (!indata_bio)
    {
        errorCode = ErrorCode::INPUT_FILE_IO_ERROR;
        return 0;
    }

    /*
    indata = read_binary_into_buffer(infile, &original_cab_file_size);

    if (memcmp(indata, CAB_DISTINCT_BYTES, sizeof(CAB_DISTINCT_BYTES))) {
        errorCode = ErrorCode::CAB_FILE_DISTINCT_BYTES_MISMATCH;
        return 0;
    }
    */

    if ((original_cab_file_size = file_size(indata_bio)) == 0)
    {
        errorCode = ErrorCode::INPUT_FILE_IO_ERROR;
        return 0;
    }

    unsigned char distinct_bytes[CAB_DISTINCT_BYTES_SIZE] = { 0 };
    if (!read_exact(OFFSET_CAB_DISTINCT_BYTES, distinct_bytes, sizeof(distinct_bytes)))
    {
        errorCode = ErrorCode::INPUT_FILE_IO_ERROR;
        return 0;
    }

    if (memcmp(distinct_bytes, CAB_DISTINCT_BYTES, sizeof(CAB_DISTINCT_BYTES)))
    {
        errorCode = ErrorCode::CAB_FILE_DISTINCT_BYTES_MISMATCH;
        return 0;
    }

    md = EVP_MD_fetch(nullptr, OSSL_DIGEST_NAME_SHA2_256, nullptr);

    hash = BIO_new(BIO_f_md());
    if (!BIO_set_md(hash, md)) {

        EVP_MD_free(md);
        md = nullptr;
        // I won't know if this set_md is successful when I'm in the destructor, 
        // I must make sure when I'm in destructor, either (1) "hash" and "md" are both
        // initialized and connected, so that BIO_free_all(hash) can free both
        // or (2) only "hash" is initialized and "md" is already freed, so that BIO_free_all(hash)
        // is still good and can free "hash". 
        // I must not have "hash" and "md" both initialized but not connected when I'm in the destructor
        
        
        errorCode = ErrorCode::HASH_BIO_SETUP_FAIL;
        return 0;
    }
    /* Create outdata file */
    outdata = BIO_new_file(outfile, "w+bx");
    if (!outdata && errno != EEXIST)
        outdata = BIO_new_file(outfile, "w+b");
    if (!outdata) {
        errorCode = ErrorCode::CREATE_OUTPUT_FILE_FAIL;
        return 0;
    }
    
    /* Push hash on outdata, if hash is NULL the function does nothing */
    BIO_push(hash, outdata);
    output_file_path = OPENSSL_strdup(outfile);

    return 1;
}

CabFileSigner::~CabFileSigner()
{
    if (hash != nullptr)
        BIO_free_all(hash);

    if (indata_bio != nullptr)
        BIO_free(indata_bio);

    if (p7 != nullptr)
        PKCS7_free(p7);

    if (errorCode != ErrorCode::OK && output_file_path != nullptr)
        remove(output_file_path);

    if (output_file_path != nullptr)
        OPENSSL_free(output_file_path);
}

char const* CabFileSigner::getError()
{
    switch (errorCode)
    {
    case ErrorCode::CAB_FILE_DISTINCT_BYTES_MISMATCH:
        return "Cab file first 4 bytes not MSCF";
        // fill out the rest of error codes
    default:
        return "unknown error";
    }
}

/*
 * [in] ctx: structure holds input and output data
 * [returns] the size of the message digest when passed an EVP_MD structure (the size of the hash)
 */
int CabFileSigner::get_hash_size()
{
    return EVP_MD_size(md);
}

EVP_MD const* CabFileSigner::get_md() const
{
    return md;
}

/*
 * Allocate and return SpcLink object.
 * [out] p: SpcLink data
 * [out] plen: SpcLink data length
 * [in] ctx: structure holds input and output data (unused)
 * [returns] pointer to ASN1_OBJECT structure corresponding to SPC_CAB_DATA_OBJID
 */
ASN1_OBJECT* CabFileSigner::spc_indirect_data_attributetypeandoptionalvalue_get(u_char** p, int* plen)
{
    ASN1_OBJECT* dtype = NULL;
    SpcLink* link = spc_link_obsolete_get();

    *plen = i2d_SpcLink(link, NULL);
    *p = (u_char*)OPENSSL_malloc((size_t)*plen);
    i2d_SpcLink(link, p);
    *p -= *plen;
    dtype = OBJ_txt2obj(SPC_CAB_DATA_OBJID, 1);
    SpcLink_free(link);
    return dtype; /* OK */
}

/*
 * Create a new PKCS#7 signature.
 * [in, out] ctx: structure holds input and output data
 * [out] hash: message digest BIO
 * [returns] pointer to PKCS#7 structure
 */
int CabFileSigner::pkcs7_signature_new(SigningCryptoParams& options)
{
    ASN1_OCTET_STRING *content;
    p7 = pkcs7_create(options, md);

    if (!p7) {
        fprintf(stderr, "Creating a new signature failed\n");
        errorCode = ErrorCode::PKCS7_NEW_SIGNATURE_FAIL;
        return 0; /* FAILED */
    }

    if (!pkcs7_signer_info_add_signed_attribute_content_type(p7)) {
        fprintf(stderr, "Adding SPC_INDIRECT_DATA_OBJID failed\n");
        errorCode = ErrorCode::ADD_SIGNED_ATTRIBUTE_CONTENT_TYPE_FAIL;
        PKCS7_free(p7);
        return 0; /* FAILED */
    }
    content = spc_indirect_data_content_create(hash, *this);
    if (!content) {
        fprintf(stderr, "Failed to get spcIndirectDataContent\n");
        errorCode = ErrorCode::SPC_INDIRECT_DATA_CONTENT_FAIL;
        return 0; /* FAILED */
    }
    if (!sign_spc_indirect_data_content(p7, content)) {
        fprintf(stderr, "Failed to set signed content\n");
        errorCode = ErrorCode::SIGN_INDIRECT_DATA_CONTENT_FAIL;
        ASN1_OCTET_STRING_free(content);
        return 0; /* FAILED */
    }
    ASN1_OCTET_STRING_free(content);
    return 1;
}

/*
 * Add signed CAB header.
 * [in, out] ctx: structure holds input and output data
 * [out] hash: message digest BIO
 * [out] outdata: outdata file BIO
 * [returns] 0 on error or 1 on success
 */
int CabFileSigner::process_header()
{
    size_t idx, written, len;
    uint32_t tmp;
    uint16_t nfolders, flags;
    u_char read_buf[128];
    u_char cfHeader_optional_fields[] = {
        0x14, 0x00, // cbCFHeader
        0x00, // cbCFFolder
        0x00, // cbCFData
        0x00, 0x00, 0x10, 0x00, // abReserve distinct bytes
        0xde, 0xad, 0xbe, 0xef, /* offset of the start of the asn1 blob */
        0xde, 0xad, 0xbe, 0xef, /* size of asn1 blob */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // redundant
    };
    //char *buf = (char*)OPENSSL_malloc(SIZE_64K);
    //memset(buf, 0, SIZE_64K);

    //char* cbCabinet_buf = (char*)OPENSSL_zalloc(CBCABINET_SIZE);
    //char* coffFiles_buf = (char*)OPENSSL_zalloc(COFFFILES_SIZE);
    //char* flags_buf = (char*)OPENSSL_zalloc(FLAGS_SIZE);

    char buf[CBCABINET_SIZE + COFFFILES_SIZE];
    memset(buf, 0, sizeof(buf));
    //char* buf = (char*)OPENSSL_zalloc(CBCABINET_SIZE + COFFFILES_SIZE);
    char* cbCabinet_buf = buf;
    char* coffFiles_buf = buf + CBCABINET_SIZE;
    char* flags_buf = buf + CBCABINET_SIZE;
    char* coffCabStart_buf = buf + CBCABINET_SIZE;

    uint32_t extra_size = CBCFHEADER_SIZE + CBCFFOLDER_SIZE + CBCFDATA_SIZE + ABRESERVE_SIZE;
    /* u1 signature[4] 4643534D MSCF: 0-3 */
    if (!read_exact(OFFSET_CAB_DISTINCT_BYTES, read_buf, CAB_DISTINCT_BYTES_SIZE))
        return 0;
    BIO_write(hash, read_buf, CAB_DISTINCT_BYTES_SIZE);
    /* u4 reserved1 00000000: 4-7 */
    if (!read_exact(OFFSET_RESERVED1, read_buf, RESERVED1_SIZE))
        return 0;
    BIO_write(outdata, read_buf, RESERVED1_SIZE);
    /* u4 cbCabinet - size of this cabinet file in bytes: 8-11 */
    if (!read_exact(OFFSET_CBCABINET, read_buf, CBCABINET_SIZE))
        return 0;

    char* p1 = static_cast<char*>(static_cast<void*>(read_buf));
    printf("%xd  %xd  %xd  %xd", p1[0], p1[1], p1[2], p1[3]);


    tmp = GET_UINT32_LE(read_buf);

    unsigned char* p = (unsigned char*)&tmp;
    printf("%xd  %xd  %xd  %xd", p[0], p[1], p[2], p[3]);
    
    
    tmp += extra_size;
    
    PUT_UINT32_LE(tmp, cbCabinet_buf);
    BIO_write(hash, cbCabinet_buf, CBCABINET_SIZE);
    /* u4 reserved2 00000000: 12-15 */
    if (!read_exact(OFFSET_RESERVED2, read_buf, RESERVED2_SIZE))
        return 0;
    BIO_write(hash, read_buf, RESERVED2_SIZE);
    /* u4 coffFiles - offset of the first CFFILE entry: 16-19 */
    if (!read_exact(OFFSET_COFFFILES, read_buf, COFFFILES_SIZE))
        return 0;
    tmp = GET_UINT32_LE(read_buf) + extra_size;
    PUT_UINT32_LE(tmp, coffFiles_buf);
    BIO_write(hash, coffFiles_buf, COFFFILES_SIZE);
    /*
     * u4 reserved3 00000000: 20-23
     * u1 versionMinor 03: 24
     * u1 versionMajor 01: 25
     * u2 cFolders - number of CFFOLDER entries in this cabinet: 26-27
     * u2 cFiles - number of CFFILE entries in this cabinet: 28-29
     */
    //memcpy(buf + 4, indata + 20, 10);
    constexpr size_t block1_size = RESERVED3_SIZE + VERSION_MINOR_SIZE + VERSION_MAJOR_SIZE + CFOLDERS_SIZE + CFILES_SIZE;
    if (!read_exact(OFFSET_RESERVED3, read_buf, block1_size))
        return 0;
    BIO_write(hash, read_buf, block1_size);

    /*u2 flags*/
    if (!read_exact(OFFSET_FLAGS, read_buf, FLAGS_SIZE))
        return 0;
    flags = GET_UINT16_LE(read_buf);
    if (flags != 0)
    {
        errorCode = ErrorCode::FLAG_NOT_ZERO;
        return 0;
    }
    //buf[4+10] = (char)flags | FLAG_RESERVE_PRESENT;
    flags = flags | FLAG_RESERVE_PRESENT;
    PUT_UINT16_LE(flags, flags_buf);
    //memcpy(buf + 16, indata + 32, 2);
    BIO_write(hash, flags_buf, FLAGS_SIZE);
    
    /* u2 setID must be the same for all cabinets in a set: 32-33 */
    //BIO_write(hash, buf + 4, 14);
    if (!read_exact(OFFSET_SETID, read_buf, SETID_SIZE))
        return 0;
    BIO_write(hash, read_buf, SETID_SIZE);
    /* u2 iCabinet - number of this cabinet file in a set: 34-35 */
    if (!read_exact(OFFSET_ICABINET, read_buf, ICABINET_SIZE))
        return 0;
    BIO_write(outdata, read_buf, ICABINET_SIZE);
    memcpy(cfHeader_optional_fields + CBCFHEADER_SIZE + CBCFFOLDER_SIZE + CBCFDATA_SIZE + ABRESERVE_DISTINCT_BYTES_SIZE, 
        cbCabinet_buf, CBCABINET_SIZE);
    BIO_write(outdata, cfHeader_optional_fields, 20);
    /*
    * Who would have known, out of the entire 24 bytes added header,
    * the last 4 bytes of the abReserve are needed in the hash.
    * This is never ever documented anywhere!
    */
    BIO_write(hash, cfHeader_optional_fields +20, 4);

    idx = OFFSET_CFFOLDER_NO_RESERVE;
    if (idx >= original_cab_file_size) {
        fprintf(stderr, "Corrupt CAB file - too short\n");
        errorCode = ErrorCode::CORRUPT_CAB_FILE_CFFOLDER_START_OVERFLOW;
        return 0; /* FAILED */
    }
    /*
     * (u8 * cFolders) CFFOLDER - structure contains information about
     * one of the folders or partial folders stored in this cabinet file
     */
    if (!read_exact(OFFSET_CFOLDERS, read_buf, CFOLDERS_SIZE))
        return 0;
    nfolders = GET_UINT16_LE(read_buf);
    if (static_cast<uint64_t>(nfolders) * CFFOLDER_SIZE_FOR_ONE >= original_cab_file_size - idx) {
        fprintf(stderr, "Corrupt cFolders value: 0x%08X\n", nfolders);
        errorCode = ErrorCode::CORRUPT_CAB_FILE_TOTAL_CFFOLDER_OVERFLOW;
        return 0; /* FAILED */
    }
    while (nfolders) {
        if (!read_exact(idx, read_buf, COFFCABSTART_SIZE))
            return 0;
        tmp = GET_UINT32_LE(read_buf);
        tmp += extra_size;
        PUT_UINT32_LE(tmp, coffCabStart_buf);
        BIO_write(hash, coffCabStart_buf, COFFCABSTART_SIZE);
        if (!read_exact(idx + COFFCABSTART_SIZE, read_buf, 4))
        BIO_write(hash, read_buf, 4);
        idx += CFFOLDER_SIZE_FOR_ONE;
        nfolders--;
    }
    //OPENSSL_free(buf);
    /* Write what's left - the compressed data bytes */
    // process remaining data
    len = original_cab_file_size - idx;
    if (BIO_seek(indata_bio, idx) < 0) // seek to offset after folders
    {
        errorCode = ErrorCode::INPUT_FILE_IO_ERROR;
        return 0;
    }
    
    char chunk_buf[4096] = { 0 };

    while (len > 0)
    {
        size_t to_read = std::min(len, sizeof(chunk_buf));
        size_t chunk_bytes_read = 0;
        if (!BIO_read_ex(indata_bio, chunk_buf, to_read, &chunk_bytes_read))
        {
            if (BIO_eof(indata_bio) <= 0)
            {
                errorCode = ErrorCode::WRITE_CFFILE_AND_CFDATA_TO_BIO_FAIL;
                return 0;
            }
            if (chunk_bytes_read < to_read && len != chunk_bytes_read)
            {
                // reached EOF sonner than expected
                errorCode = ErrorCode::WRITE_CFFILE_AND_CFDATA_TO_BIO_FAIL;
                return 0;
            }
            if (chunk_bytes_read == 0)
                break;
        }
        if (!BIO_write_ex(hash, chunk_buf, chunk_bytes_read, &written) || written != chunk_bytes_read)
        {
            errorCode = ErrorCode::WRITE_CFFILE_AND_CFDATA_TO_BIO_FAIL;
            return 0;
        }
        len -= chunk_bytes_read;
    }
    if (len != 0)
    {
        errorCode = ErrorCode::WRITE_CFFILE_AND_CFDATA_TO_BIO_FAIL;
        return 0;
    }


    /*
    while (len > 0) {
        if (!BIO_write_ex(hash, indata + idx, len, &written))
        {
            errorCode = ErrorCode::WRITE_CFFILE_AND_CFDATA_TO_BIO_FAIL;
            return 0;
        }
        len -= written;
        idx += written;
    }
    */
    return 1; /* OK */
}

/*
 * Append signature to the outfile.
 * [in, out] ctx: structure holds input and output data (unused)
 * [out] outdata: outdata file BIO
 * [in] p7: PKCS#7 signature
 * [returns] 1 on error or 0 on success
 */
int CabFileSigner::append_pkcs7()
{
    u_char* p = NULL;
    int len;       /* signature length */
    int padlen;    /* signature padding length */

    if ((len = i2d_PKCS7(p7, NULL)) <= 0)
    {
        errorCode = ErrorCode::PKCS7_DER_ENCODING_FAIL;
        return 0;
    }
    if ((p = (u_char*)OPENSSL_malloc((size_t)len)) == NULL) 
    {
        errorCode = ErrorCode::MEM_ALLOC_ENCODED_PKCS7_FAIL;
        fprintf(stderr, "i2d_PKCS memory allocation failed: %d\n", len);
        return 0; /* FAILED */
    }
    i2d_PKCS7(p7, &p);
    p -= len;
    padlen = len % 8 ? 8 - len % 8 : 0;
    BIO_write(outdata, p, len);
    /* pad (with 0's) asn1 blob to 8 byte boundary */
    if (padlen > 0) {
        memset(p, 0, (size_t)padlen);
        BIO_write(outdata, p, padlen);
    }
    OPENSSL_free(p);
    return 1; /* OK */
}


/*
 * Update additional data size.
 * Additional data size is located at offset 0x30 (from file beginning)
 * and consist of 4 bytes (little-endian order).
 * [in, out] ctx: structure holds input and output data
 * [out] outdata: outdata file BIO
 * [in] p7: PKCS#7 signature
 * [returns] none
 */
void CabFileSigner::update_data_size()
{
    int len, padlen;
    u_char buf[] = {
        0x00, 0x00, 0x00, 0x00
    };

    (void)BIO_seek(outdata, OFFSET_ABRESERVE_SIGNATURE_SIZE);
    len = i2d_PKCS7(p7, NULL);
    padlen = len % 8 ? 8 - len % 8 : 0;
    PUT_UINT32_LE(len + padlen, buf);
    BIO_write(outdata, buf, ABRESERVE_SIGNATURE_SIZE_SIZE);
}

int CabFileSigner::sign(SigningCryptoParams& params)
{
    int ret = 0;
    if (!process_header()) {
        return 0;
    }

    if (BIO_flush(hash) <= 0) // ensure all data is processed before using the hash value
    {
        return 0;
    }

    ret = pkcs7_signature_new(params);
    if (!ret) {
        return 0;
    }

    ret = append_pkcs7();
    if (!ret) {
        //PKCS7_free(p7);
        return 0;
    }

    update_data_size();

    BIO_flush(outdata);

    return 1;
}