#pragma once
const unsigned char CAB_DISTINCT_BYTES[4] = { 0x4d, 0x53, 0x43, 0x46 };
const int OFFSET_CAB_DISTINCT_BYTES = 0;
const int CAB_DISTINCT_BYTES_SIZE = 4;

const int OFFSET_RESERVED1 = 4;
const int RESERVED1_SIZE = 4;

const int OFFSET_CBCABINET = 8;
const int CBCABINET_SIZE = 4;

const int OFFSET_RESERVED2 = 12;
const int RESERVED2_SIZE = 4;

const int OFFSET_COFFFILES = 16;
const int COFFFILES_SIZE = 4;

const int OFFSET_RESERVED3 = 20;
const int RESERVED3_SIZE = 4;

const int OFFSET_VERSION_MINOR = 24;
const int VERSION_MINOR_SIZE = 1;

const int OFFSET_VERSION_MAJOR = 25;
const int VERSION_MAJOR_SIZE = 1;

const int OFFSET_CFOLDERS = 26;
const int CFOLDERS_SIZE = 2;

const int OFFSET_CFILES = 28;
const int CFILES_SIZE = 2;

const int OFFSET_FLAGS = 30;
const int FLAGS_SIZE = 2;

const int OFFSET_SETID = 32;
const int SETID_SIZE = 2;

const int OFFSET_ICABINET = 34;
const int ICABINET_SIZE = 2;

const unsigned char CBCFHEADER_VALUE_FOR_SIGNING[2] = { 0x14, 0x00 }; // little endian, decimal 20
const int OFFSET_CBCFHEADER = 36;
const int CBCFHEADER_SIZE = 2;


const int OFFSET_CBCFFOLDER = 38;
const int CBCFFOLDER_SIZE = 1;

const int OFFSET_CBCFDATA = 39;
const int CBCFDATA_SIZE = 1;

const int OFFSET_ABRESERVE = 40;
const int ABRESERVE_SIZE = 20;

const unsigned char ABRESERVE_DISTINCT_BYTES_FOR_SIGNING[4] = { 0x00, 0x00, 0x10, 0x00 };
const int OFFSET_ABRESERCE_DISTINCT_BYTES = OFFSET_ABRESERVE;
const int ABRESERVE_DISTINCT_BYTES_SIZE = 4;

const int OFFSET_ABRESERVE_SIGNATURE_OFFSET = 44;
const int ABRESERVE_SIGNATURE_OFFSET_SIZE = 4;

const int OFFSET_ABRESERVE_SIGNATURE_SIZE = 48;
const int ABRESERVE_SIGNATURE_SIZE_SIZE = 4;

const int OFFSET_ABRESERVE_REDUNDANT = 52;
const int ABRESERVE_REDUNDANT_SIZE = 8;

const int OFFSET_CFFOLDER_NO_RESERVE = OFFSET_CBCFHEADER;
const int CFFOLDER_SIZE_FOR_ONE = 8;

const int COFFCABSTART_SIZE = 4;



class CabFileSigner
{
private:
    typedef unsigned char u_char;

    enum class ErrorCode
    {
        OK = 0,
        CAB_FILE_DISTINCT_BYTES_MISMATCH,
        HASH_BIO_SETUP_FAIL,
        CREATE_OUTPUT_FILE_FAIL,
        PKCS7_NEW_SIGNATURE_FAIL,
        ADD_SIGNED_ATTRIBUTE_CONTENT_TYPE_FAIL,
        SPC_INDIRECT_DATA_CONTENT_FAIL,
        SIGN_INDIRECT_DATA_CONTENT_FAIL,
        FLAG_NOT_ZERO,
        CORRUPT_CAB_FILE_CFFOLDER_START_OVERFLOW,
        CORRUPT_CAB_FILE_TOTAL_CFFOLDER_OVERFLOW,
        WRITE_CFFILE_AND_CFDATA_TO_BIO_FAIL,
        PKCS7_DER_ENCODING_FAIL,
        MEM_ALLOC_ENCODED_PKCS7_FAIL,
        INPUT_FILE_IO_ERROR,
    };

    BIO* indata_bio;
    size_t original_cab_file_size;
    BIO* hash;
    BIO* outdata;
    EVP_MD* md;
    //char* indata;
    PKCS7* p7;
    ErrorCode errorCode;
    char* output_file_path;

    bool read_exact(size_t offset, void* buf, size_t len);

public:
    CabFileSigner();
    CabFileSigner(char const* infile, char const* outfile);
    ~CabFileSigner();
    int init(char const* infile, char const* outfile);
    int sign(SigningCryptoParams& params);
    int get_hash_size();
    EVP_MD const* get_md() const;
    int process_header();
    int pkcs7_signature_new(SigningCryptoParams& options);
    int append_pkcs7();
    void update_data_size();
    ASN1_OBJECT* spc_indirect_data_attributetypeandoptionalvalue_get(u_char** p, int* len);
    char const* getError();
};