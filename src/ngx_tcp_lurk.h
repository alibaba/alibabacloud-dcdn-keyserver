
/*
 * Copyright (C) zuxi.wzx (jinjiu)
 * Copyright (C) Aliyun, Inc.
 */


#ifndef _NGX_TCP_LURK_H_INCLUDED_
#define _NGX_TCP_LURK_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/conf.h>


#if !defined(htonll) && !defined(ntohll)

#if (NGX_HAVE_LITTLE_ENDIAN)
#define htonll(x) ((((uint64_t)htonl((x) & 0xFFFFFFFF)) << 32) | htonl((x) >> 32))
#define ntohll(x) ((((uint64_t)ntohl((x) & 0xFFFFFFFF)) << 32) | ntohl((x) >> 32))
#else
#define htonll(x) (x)
#define ntohll(x) (x)
#endif

#endif


#define NGX_LURK_PROTO_TAG_SNI              1
#define NGX_LURK_PROTO_TAG_CLIENT_IP        2
#define NGX_LURK_PROTO_TAG_CLIENT_IPV6      3
#define NGX_LURK_PROTO_TAG_KEY              4


#if (NGX_HAVE_PACK_PRAGMA)
#pragma pack(push, 1)
#elif (NGX_SOLARIS)
#pragma pack(1)
#else
#error "lurk SSL needs structure packing pragma support"
#endif


typedef struct {
    uint8_t                         length;
    uint8_t                         value[0];
} ngx_lurk_opaque8_t;


typedef struct {
    uint16_t                        length;
    uint8_t                         value[0];
} ngx_lurk_opaque16_t;


typedef struct {
    uint8_t                         qrv; /* q:1, reserved:4, version:3 */
    uint8_t                         type;
    uint64_t                        id;
} ngx_lurk_query_header_t;


typedef struct {
    ngx_lurk_query_header_t         query_header;
    uint8_t                         status;
} ngx_lurk_response_header_t;


typedef struct {
    uint8_t                         type;
    ngx_lurk_opaque8_t              data;
} ngx_lurk_key_pair_id_t;


typedef struct {
    uint8_t                         master_prf;
    uint8_t                         client_random[32];
    uint8_t                         edge_server_random[32];
    uint16_t                        client_version;
    uint16_t                        edge_server_version;
    ngx_lurk_opaque16_t             encryped_pre_master_secret;
} ngx_lurk_tls_master_rsa_input_payload_t;


typedef struct {
    uint8_t                         master_prf;
    uint8_t                         session_prf;
    uint8_t                         client_random[32];
    uint8_t                         edge_server_random[32];
    uint16_t                        client_version;
    uint16_t                        edge_server_version;
} ngx_lurk_tls_extended_master_rsa_entity_t;


typedef struct {
    uint8_t                          master[48];
} ngx_lurk_tls_master_payload_t;


typedef struct {
    uint8_t                          client_random[32];
    uint8_t                          edge_server_random[32];
    uint16_t                         version;
    uint16_t                         signature_scheme;
    uint8_t                          ecdhe_params[0];
} ngx_lurk_tls_ecdhe_input_payload_t;


typedef struct {
    uint8_t                          client_random[32];
    uint8_t                          edge_server_random[32];
    uint16_t                         version;
} ngx_lurk_tls_chaos_enc_info_t;


typedef struct {
    uint8_t                          tag;
    uint16_t                         length;
} ngx_lurk_proto_item_t;


typedef struct {
    uint16_t                         version;
    uint16_t                         signature_scheme;
} ngx_lurk_tls_cert_verify_entity_t;


#if (NGX_HAVE_PACK_PRAGMA)
#pragma pack(pop)
#elif (NGX_SOLARIS)
#pragma pack()
#else
#error "lurk SSL needs structure packing pragma support"
#endif


typedef enum {
    NGX_LURK_QUERY_BIT_RESPONSE                         = 0,
    NGX_LURK_QUERY_BIT_QUERY                            = 1,
} ngx_lurk_query_bit_t;


typedef enum {
    NGX_LURK_VERSION_MIN                                = 1,
    NGX_LURK_V1                                         = 1,
    NGX_LURK_V2                                         = 2,
    NGX_LURK_V3                                         = 3,
    NGX_LURK_V4                                         = 4,
    NGX_LURK_VERSION_MAX                                = 4,
} ngx_lurk_version_t;


typedef enum {
    NGX_LURK_QUERY_TYPE_PING                            = 0,
    NGX_LURK_QUERY_TYPE_CAP                             = 1,
    NGX_LURK_QUERY_TYPE_RSA_MASTER                      = 2,
    NGX_LURK_QUERY_TYPE_RSA_EXTENDED_MASTER             = 3,
    NGX_LURK_QUERY_TYPE_PFS_RSA_MASTER                  = 4,
    NGX_LURK_QUERY_TYPE_ECDHE                           = 5,
    NGX_LURK_QUERY_TYPE_PFS_NON_PREDICTABLE_ECDHE       = 6,
    NGX_LURK_QUERY_TYPE_CERT_VERIFY                     = 7,
} ngx_lurk_query_type_t;


typedef enum {
    NGX_LURK_RESPONSE_SUCCESS                           = 0,
    NGX_LURK_RESPONSE_UNVALID_LURK_VERSION              = 1,
    NGX_LURK_RESPONSE_UNVALID_QUERY_TYPE                = 2,
    NGX_LURK_RESPONSE_UNVALID_KEY_PAIR_ID_FORMAT        = 3,
    NGX_LURK_RESPONSE_UNVALID_KEY_PAIR_ID               = 4,
    NGX_LURK_RESPONSE_UNVALID_ENCRYPTED_MASTER_LENGTH   = 5,
    NGX_LURK_RESPONSE_UNVALID_PRF                       = 6,
    NGX_LURK_RESPONSE_UNVALID_TLS_VERSION               = 7,
    NGX_LURK_RESPONSE_UNVALID_PAYLOAD_FORMAT            = 8,
    NGX_LURK_RESPONSE_ERROR_INTERNAL                    = 9,
    NGX_LURK_RESPONSE_ERROR_OVERWHELM                   = 10,
} ngx_lurk_respone_status_t;


typedef enum {
    NGX_LURK_KEY_PAIR_ID_TYPE_SHA256                    = 0,
} ngx_lurk_key_pair_id_type_t;


#define NGX_LURK_KEY_PAIR_ID_SHA256_LEN                 32


/* RFC5246 section 6.1 */
typedef enum {
    NGX_LURK_TLS_PRF_SHA256                             = 0,
    NGX_LURK_TLS_PRF_SHA384                             = 1,
    NGX_LURK_TLS_PRF_MD5SHA1                            = 2,
} ngx_lurl_prf_algorithm_t;

#endif /* _NGX_TCP_LURK_H_INCLUDED_ */
