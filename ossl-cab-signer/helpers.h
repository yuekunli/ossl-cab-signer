#pragma once

uint32_t get_file_size(const char* infile);
char* map_file(const char* infile, const size_t size);
void unmap_file(char* indata);

char* read_binary_into_buffer(char const* file_path, size_t* _size);


SpcLink* spc_link_obsolete_get(void);

PKCS7* pkcs7_create(GLOBAL_OPTIONS& options, EVP_MD const* md);

int pkcs7_signer_info_add_signed_attribute_content_type(PKCS7* p7);

ASN1_OCTET_STRING* spc_indirect_data_content_create(BIO* hash, CabFileController& cab);

int sign_spc_indirect_data_content(PKCS7* p7, ASN1_OCTET_STRING* content);

static STACK_OF(X509)* X509_chain_get_sorted(GLOBAL_OPTIONS& options, int signer);
