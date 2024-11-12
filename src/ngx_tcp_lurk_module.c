/*
 * Copyright (C) zuxi.wzx (jinjiu)
 * Copyright (C) Aliyun, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_tcp.h>

#include <assert.h>

#include <openssl/ssl.h>
#include <openssl/md5.h>
#if OPENSSL_VERSION_NUMBER >= 0x10100003L
#include <openssl/kdf.h>
#endif

#include <ngx_tcp_lurk.h>


#if defined(ngx_lurk_log_error)
#undef ngx_lurk_log_error
#endif

#define ngx_lurk_log_error(level, log, errno, fmt, args...)                        \
    ngx_log_error(level, log, errno, "[tcp lurk][func:%s][line:%d][keyclient:%V]"fmt, \
            __func__, __LINE__, &s->connection->addr_text, ##args)

#define NGX_ARRAY_LENGTH(array) (sizeof(array)/sizeof((array)[0]))
#define NGX_TCP_LURK_REG_INTERVAL_MSEC  5000

#define NGX_TCP_LURK_HTTP_HEADER_ACCEPT        "application/json"
#define NGX_TCP_LURK_HTTP_HEADER_ACCEPT_LEN    sizeof(NGX_TCP_LURK_HTTP_HEADER_ACCEPT) - 1

#define NGX_TCP_LURK_KEY_ID_LEN                32
#define NGX_TCP_LURK_CATEGORY_MASK_MIN         0
#define NGX_TCP_LURK_CATEGORY_MASK_MAX         1024

#define NGX_TCP_LURK_HEALTH_REQ "GET /lurk.hck HTTP/"
#define NGX_TCP_LURK_HEALTH_REQ_L (sizeof(NGX_TCP_LURK_HEALTH_REQ) - 1)
#define NGX_TCP_LURK_HEALTH_RESP "HTTP/1.0 200 OK\r\n\r\n"
#define NGX_TCP_LURK_HEALTH_RESP_L (sizeof(NGX_TCP_LURK_HEALTH_RESP) - 1)

#define NGX_TCP_LURK_STATUS_URI "/lurk.st"

#define NGX_TCP_LURK_STATUS_HEADER "HTTP/1.0 200 OK\r\n\r\nreqs  acpts kplvs ereqs\
 dcrpt sign  vrfy  rsa   ecc   rtime nokey evers eform etype eintn\
 edecr emstr esign evrfy ewrt  eread rtout\
 wtout unmsg\n"

#define NGX_TCP_LURK_PROTOCOL                           4443

#ifndef NGX_LOG_DEBUG_TCP
#define NGX_LOG_DEBUG_TCP                               0x800
#endif

#define NGX_TCP_LURK_FLAG_NONE                          0x00
#define NGX_TCP_LURK_FLAG_DONE                          0x01
#define NGX_TCP_LURK_FLAG_PROCESSING                    0x02
#define NGX_TCP_LURK_FLAG_RETRY                         0x03

#define NGX_TCP_LURK_PHASE_START                        0
#define NGX_TCP_LURK_PHASE_REGISTER                     1
#define NGX_TCP_LURK_PHASE_READY                        2

#ifndef TLSEXT_hash_none
#define TLSEXT_hash_none                                0
#endif
#ifndef TLSEXT_hash_md5
#define TLSEXT_hash_md5                                 1
#endif
#ifndef TLSEXT_hash_sha1
#define TLSEXT_hash_sha1                                2
#endif
#ifndef TLSEXT_hash_sha224
#define TLSEXT_hash_sha224                              3
#endif
#ifndef TLSEXT_hash_sha256
#define TLSEXT_hash_sha256                              4
#endif
#ifndef TLSEXT_hash_sha384
#define TLSEXT_hash_sha384                              5
#endif
#ifndef TLSEXT_hash_sha512
#define TLSEXT_hash_sha512                              6
#endif

#ifndef TLSEXT_signature_anonymous
#define TLSEXT_signature_anonymous                      0
#endif
#ifndef TLSEXT_signature_rsa
#define TLSEXT_signature_rsa                            1
#endif
#ifndef TLSEXT_signature_dsa
#define TLSEXT_signature_dsa                            2
#endif
#ifndef TLSEXT_signature_ecdsa
#define TLSEXT_signature_ecdsa                          3
#endif

#ifndef SSL_R_UNSUPPORTED_DIGEST_TYPE
#define SSL_R_UNSUPPORTED_DIGEST_TYPE                   326
#endif

#ifndef SSL_F_TLS1_PRF
#define SSL_F_TLS1_PRF                                  284
#endif

#ifndef NID_hmac
#define NID_hmac                                        855
#endif

#ifndef EVP_PKEY_HMAC
#define EVP_PKEY_HMAC                                   NID_hmac
#endif

#ifndef TLS1_2_VERSION
#define TLS1_2_VERSION                                  0x0303
#endif


typedef struct {
    ngx_queue_t               queue;
    ngx_chain_t              *chain;
} ngx_tcp_lurk_http_body_chain_t;


typedef struct ngx_tcp_lurk_conf_s {
    ngx_flag_t                enable;

    ngx_str_t                 pkey_path;
    ngx_rbtree_t              pkey_tree;
    ngx_rbtree_node_t         pkey_sentinel;
    ngx_queue_t               pkey_queue;

    ngx_msec_t                send_timeout;
    ngx_msec_t                read_timeout;
    ngx_msec_t                keepalive_timeout;
    ngx_uint_t                keepalive_requests;

    ngx_str_t                 health_check;
    ngx_str_t                 status_uri;
    ngx_str_t                 status_req_line;

    size_t                    buffer_size;

    ngx_array_t               *limit_keyid_arr;

} ngx_tcp_lurk_conf_t;


typedef struct {
    ngx_buf_t                 buf;
    ngx_buf_t                 header;
    ngx_buf_t                 body;
} ngx_tcp_lurk_buf_t;


typedef struct {
    ngx_rbtree_t             *tree;
    ngx_queue_t              *queue;
    ngx_pool_t               *pool;
} ngx_tcp_lurk_walk_tree_data_t;


typedef struct {
    ngx_uint_t                state;
    ngx_flag_t                flag;

    /* request */
    uint8_t                   version;
    uint8_t                   type;
    uint64_t                  id;
    ngx_str_t                 servername;
    ngx_str_t                 key_id;
    u_char                    key_id_hex[64];
    ngx_lurk_query_header_t  *header;
    ngx_buf_t                 payload;

    uint32_t                  client_ip;
#if (NGX_HAVE_INET6)
    unsigned char             client_ipv6[16];   /* IPv6 address */
#endif
    ngx_str_t                 ip_text;

    ngx_tcp_lurk_buf_t       *buf;
    ngx_int_t                 buf_len;

    EVP_PKEY                 *evp_pkey;
    ngx_int_t                 pkey_size;

    /* response */
    uint8_t                   err;
    uint8_t                   in_process;

    ngx_str_t                 decrypt_res;

    long                      master_prf;
    ngx_queue_t               http_body;
    ngx_uint_t                http_body_len;

    struct timeval            start_tv;

    uint8_t                   enc_key[SSL3_RANDOM_SIZE];
    uint8_t                   dec_key[SSL3_RANDOM_SIZE];
    uint8_t                   client_random[SSL3_RANDOM_SIZE];
    uint8_t                   server_random[SSL3_RANDOM_SIZE];
    ngx_str_t                 private_key_str;

    ngx_lurk_tls_master_rsa_input_payload_t     *rsa;
#if OPENSSL_VERSION_NUMBER >= 0x10100003L
    ngx_lurk_tls_extended_master_rsa_entity_t   *ems_rsa;
#endif
} ngx_tcp_lurk_ctx_t;


typedef struct {
    ngx_atomic_t               requests;
    ngx_atomic_t               fail_requests;
    ngx_atomic_t               master_secret;
    ngx_atomic_t               sign;
    ngx_atomic_t               cert_verify;
    ngx_atomic_t               pkey_rsa;
    ngx_atomic_t               pkey_ecc;
    ngx_atomic_t               rt;
    ngx_atomic_t               no_key;
    ngx_atomic_t               bad_format;
    ngx_atomic_t               bad_version;
    ngx_atomic_t               bad_type;
    ngx_atomic_t               fail_internal;
    ngx_atomic_t               fail_decrypt;
    ngx_atomic_t               fail_master_secret;
    ngx_atomic_t               fail_sign;
    ngx_atomic_t               fail_cert_verify;
    ngx_atomic_t               fail_write;
    ngx_atomic_t               fail_read;
    ngx_atomic_t               rtimeout;
    ngx_atomic_t               wtimeout;
    ngx_atomic_t               accepts;
    ngx_atomic_t               keepalives;
    ngx_atomic_t               fail_unknown_msg;
} ngx_tcp_lurk_server_status_t;


typedef struct {
    ngx_event_t                ev;
    ngx_int_t                  limit;
    ngx_int_t                  remain;
} ngx_lurk_limit_keyid_t;


typedef struct {
    ngx_rbtree_node_t          node;
    ngx_queue_t                queue;

    EVP_PKEY                  *pkey;     // 本地加载秘钥时使用

    ngx_int_t                  size;
    uint8_t                    key_id[NGX_TCP_LURK_KEY_ID_LEN];

    ngx_int_t                  refcnt;
    uint8_t                    cat_mask[NGX_TCP_LURK_CATEGORY_MASK_MAX / 8];
    uint8_t                    key[0];
} ngx_tcp_lurk_key_node_t;


typedef struct ngx_tcp_lurk_main_conf_s {
    ngx_flag_t                 remote;
    ngx_str_t                  get_key_mode;

    ngx_queue_t                http_body;
    ngx_uint_t                 http_body_len;
} ngx_tcp_lurk_main_conf_t;


ngx_int_t       ngx_tcp_lurk_overwhelm;

ngx_atomic_t    ngx_lurk_requests0;
ngx_atomic_t   *ngx_lurk_requests = &ngx_lurk_requests0;

ngx_atomic_t    ngx_lurk_fail_requests0;
ngx_atomic_t   *ngx_lurk_fail_requests = &ngx_lurk_fail_requests0;

ngx_atomic_t    ngx_lurk_response_time0;
ngx_atomic_t   *ngx_lurk_response_time = &ngx_lurk_response_time0;

ngx_atomic_t    ngx_lurk_request_master_secret0;
ngx_atomic_t   *ngx_lurk_request_master_secret = &ngx_lurk_request_master_secret0;

ngx_atomic_t    ngx_lurk_request_sign0;
ngx_atomic_t   *ngx_lurk_request_sign = &ngx_lurk_request_sign0;

ngx_atomic_t    ngx_lurk_request_cert_verify0;
ngx_atomic_t   *ngx_lurk_request_cert_verify = &ngx_lurk_request_cert_verify0;

ngx_atomic_t    ngx_lurk_pkey_rsa0;
ngx_atomic_t   *ngx_lurk_pkey_rsa = &ngx_lurk_pkey_rsa0;

ngx_atomic_t    ngx_lurk_pkey_ecc0;
ngx_atomic_t   *ngx_lurk_pkey_ecc = &ngx_lurk_pkey_ecc0;

ngx_atomic_t    ngx_lurk_fail_no_key0;
ngx_atomic_t   *ngx_lurk_fail_no_key = &ngx_lurk_fail_no_key0;

ngx_atomic_t    ngx_lurk_fail_bad_format0;
ngx_atomic_t   *ngx_lurk_fail_bad_format = &ngx_lurk_fail_bad_format0;

ngx_atomic_t    ngx_lurk_fail_bad_version0;
ngx_atomic_t   *ngx_lurk_fail_bad_version = &ngx_lurk_fail_bad_version0;

ngx_atomic_t    ngx_lurk_fail_bad_type0;
ngx_atomic_t   *ngx_lurk_fail_bad_type = &ngx_lurk_fail_bad_type0;

ngx_atomic_t    ngx_lurk_fail_internal0;
ngx_atomic_t   *ngx_lurk_fail_internal = &ngx_lurk_fail_internal0;

ngx_atomic_t    ngx_lurk_fail_decrypt0;
ngx_atomic_t   *ngx_lurk_fail_decrypt = &ngx_lurk_fail_decrypt0;

ngx_atomic_t    ngx_lurk_fail_master_secret0;
ngx_atomic_t   *ngx_lurk_fail_master_secret = &ngx_lurk_fail_master_secret0;

ngx_atomic_t    ngx_lurk_fail_sign0;
ngx_atomic_t   *ngx_lurk_fail_sign = &ngx_lurk_fail_sign0;

ngx_atomic_t    ngx_lurk_fail_cert_verify0;
ngx_atomic_t   *ngx_lurk_fail_cert_verify = &ngx_lurk_fail_cert_verify0;

ngx_atomic_t    ngx_lurk_fail_write0;
ngx_atomic_t   *ngx_lurk_fail_write = &ngx_lurk_fail_write0;

ngx_atomic_t    ngx_lurk_fail_read0;
ngx_atomic_t   *ngx_lurk_fail_read = &ngx_lurk_fail_read0;

ngx_atomic_t    ngx_lurk_fail_rtimeout0;
ngx_atomic_t   *ngx_lurk_fail_rtimeout = &ngx_lurk_fail_rtimeout0;

ngx_atomic_t    ngx_lurk_fail_wtimeout0;
ngx_atomic_t   *ngx_lurk_fail_wtimeout = &ngx_lurk_fail_wtimeout0;

ngx_atomic_t    ngx_lurk_fail_unknown_msg0;
ngx_atomic_t   *ngx_lurk_fail_unknown_msg = &ngx_lurk_fail_unknown_msg0;

ngx_atomic_t    ngx_lurk_accepts0;
ngx_atomic_t   *ngx_lurk_accepts = &ngx_lurk_accepts0;

ngx_atomic_t    ngx_lurk_keepalives0;
ngx_atomic_t   *ngx_lurk_keepalives = &ngx_lurk_keepalives0;

ngx_uint_t      ngx_lurk_stat_count;

static ngx_hash_t lurk_limit_keyid_runtime_tb;


int ngx_tcp_lurk_tls1_prf(unsigned char *out, long digest_mask,
    const void *seed1, int seed1_len, const void *seed2, int seed2_len,
    const void *seed3, int seed3_len, const void *seed4, int seed4_len,
    const void *seed5, int seed5_len, const unsigned char *sec, int slen);

#if OPENSSL_VERSION_NUMBER >= 0x10100003L
int ngx_tcp_lurk_tls1_prf_v2(long digest_mask,
    const void *seed1, size_t seed1_len,
    const void *seed2, size_t seed2_len,
    const void *seed3, size_t seed3_len,
    const void *seed4, size_t seed4_len,
    const void *seed5, size_t seed5_len,
    const unsigned char *sec, size_t slen,
    unsigned char *out, size_t olen);
#endif

int ngx_tcp_lurk_ssl3_prf(unsigned char *out,
    const void *client_random, int client_random_len,
    const void *server_random, int server_random_len,
    const unsigned char *p, int len);

ngx_int_t ngx_tcp_lurk_prf(unsigned char *out, uint16_t version,
    long master_prf, const void *client_random, int client_random_len,
    const void *server_random, int server_random_len,
    const unsigned char *p, int len);

#if OPENSSL_VERSION_NUMBER >= 0x10100003L
ngx_int_t ngx_tcp_lurk_prf_ems(unsigned char *out, uint16_t version,
    long master_prf, const void *client_random, int client_random_len,
    const void *server_random, int server_random_len,
    const void *session_hash, int hashlen,
    const unsigned char *p, int len);
#endif

static ngx_int_t ngx_tcp_lurk_init_module(ngx_cycle_t *cf);
static void ngx_tcp_lurk_init_session(ngx_tcp_session_t *s);
static char *ngx_tcp_lurk(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void ngx_tcp_lurk_read_handler(ngx_event_t *ev);
static void ngx_tcp_lurk_write_handler(ngx_event_t *ev);
static void ngx_tcp_lurk_read(ngx_tcp_session_t *s);
static void ngx_tcp_lurk_write(ngx_tcp_session_t *s);
static void *ngx_tcp_lurk_create_srv_conf(ngx_conf_t *cf);
static char *ngx_tcp_lurk_merge_srv_conf(ngx_conf_t *cf, void *parent,
    void *child);
static ngx_int_t ngx_tcp_lurk_parse_request(ngx_tcp_session_t *s);
static ngx_int_t ngx_tcp_lurk_process_request(ngx_tcp_session_t *s);
static void ngx_tcp_lurk_keepalive_handler(ngx_event_t *rev);
static void ngx_tcp_lurk_finalize_session(ngx_tcp_session_t *s,
    ngx_int_t keepalive);
static void ngx_tcp_lurk_limit_keyid_handler(ngx_event_t *ev);

static void *ngx_tcp_lurk_create_main_conf(ngx_conf_t *cf);
static char *ngx_tcp_lurk_init_main_conf(ngx_conf_t *cf, void *conf);
static ngx_int_t ngx_tcp_lurk_limit_keyid(ngx_tcp_session_t *s);
static int hex2i(char ch);
static void ngx_tcp_lurk_get_common_name(SSL *ssl, char *cn, size_t size);
static ngx_int_t ngx_ssl_lurk_encrypt(ngx_str_t *key, ngx_str_t *in,
    ngx_str_t *out);
static ngx_int_t ngx_ssl_lurk_decrypt(ngx_str_t *key, ngx_str_t *in,
    ngx_str_t *out);
static ngx_int_t ngx_tcp_lurk_dispatch(ngx_tcp_session_t *s);


static u_char *ngx_tcp_lurk_get_start_time(ngx_tcp_session_t *s, u_char *buf,
    ngx_tcp_log_op_t *op);
static u_char *ngx_tcp_lurk_get_id(ngx_tcp_session_t *s, u_char *buf,
    ngx_tcp_log_op_t *op);
static u_char *ngx_tcp_lurk_get_pkey_id_hex(ngx_tcp_session_t *s, u_char *buf,
    ngx_tcp_log_op_t *op);
static u_char *ngx_tcp_lurk_get_sni(ngx_tcp_session_t *s, u_char *buf,
    ngx_tcp_log_op_t *op);
static u_char *ngx_tcp_lurk_get_type(ngx_tcp_session_t *s, u_char *buf,
    ngx_tcp_log_op_t *op);
static u_char *ngx_tcp_lurk_get_client(ngx_tcp_session_t *s, u_char *buf,
    ngx_tcp_log_op_t *op);
static u_char *ngx_tcp_lurk_get_error(ngx_tcp_session_t *s, u_char *buf,
    ngx_tcp_log_op_t *op);

void ngx_tcp_lurk_shm_free_key_node(ngx_tcp_lurk_key_node_t *key_node);


static inline int
ngx_tcp_lurk_test_cat_mask(uint8_t *mask, int cat)
{
    return mask[cat / 8] & (1 << (cat % 8));
}


static inline void
ngx_tcp_lurk_set_cat_mask(uint8_t *mask, int cat)
{
    mask[cat / 8] |= 1 << (cat % 8);
}


static inline void
ngx_tcp_lurk_reset_cat_mask(uint8_t *mask, int cat)
{
    mask[cat / 8] &= ~(1 << (cat % 8));
}


static ngx_shm_t  stats_shm;


static ngx_tcp_protocol_t  ngx_tcp_lurk_protocol = {

    ngx_string("tcp_lurk"),
    { 0, 0, 0, 0 },
    NGX_TCP_LURK_PROTOCOL,
    ngx_tcp_lurk_init_session,
    NULL,
    NULL,
    ngx_string("Internal server error" CRLF)

};


static ngx_command_t  ngx_tcp_lurk_commands[] = {
    { ngx_string("lurk_get_key_mode"),
      NGX_TCP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_TCP_MAIN_CONF_OFFSET,
      offsetof(ngx_tcp_lurk_main_conf_t, get_key_mode),
      NULL },

    { ngx_string("lurk"),
      NGX_TCP_MAIN_CONF|NGX_TCP_SRV_CONF|NGX_CONF_NOARGS,
      ngx_tcp_lurk,
      NGX_TCP_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("lurk_pkey_path"),
      NGX_TCP_MAIN_CONF|NGX_TCP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_TCP_SRV_CONF_OFFSET,
      offsetof(ngx_tcp_lurk_conf_t, pkey_path),
      NULL },

    { ngx_string("lurk_read_timeout"),
      NGX_TCP_MAIN_CONF|NGX_TCP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_TCP_SRV_CONF_OFFSET,
      offsetof(ngx_tcp_lurk_conf_t, read_timeout),
      NULL },

    { ngx_string("lurk_send_timeout"),
      NGX_TCP_MAIN_CONF|NGX_TCP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_TCP_SRV_CONF_OFFSET,
      offsetof(ngx_tcp_lurk_conf_t, send_timeout),
      NULL },

    { ngx_string("lurk_keepalive_timeout"),
      NGX_TCP_MAIN_CONF|NGX_TCP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_TCP_SRV_CONF_OFFSET,
      offsetof(ngx_tcp_lurk_conf_t, keepalive_timeout),
      NULL },

    { ngx_string("lurk_keepalive_requests"),
      NGX_TCP_MAIN_CONF|NGX_TCP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_TCP_SRV_CONF_OFFSET,
      offsetof(ngx_tcp_lurk_conf_t, keepalive_requests),
      NULL },

    { ngx_string("lurk_health_check"),
      NGX_TCP_MAIN_CONF|NGX_TCP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_TCP_SRV_CONF_OFFSET,
      offsetof(ngx_tcp_lurk_conf_t, health_check),
      NULL },

    { ngx_string("lurk_status_uri"),
      NGX_TCP_MAIN_CONF|NGX_TCP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_TCP_SRV_CONF_OFFSET,
      offsetof(ngx_tcp_lurk_conf_t, status_uri),
      NULL },

    { ngx_string("lurk_limit_keyid"),
      NGX_TCP_MAIN_CONF|NGX_TCP_SRV_CONF|NGX_CONF_TAKE2,
      ngx_conf_set_keyval_slot,
      NGX_TCP_SRV_CONF_OFFSET,
      offsetof(ngx_tcp_lurk_conf_t, limit_keyid_arr),
      NULL },

    ngx_null_command
};


static ngx_tcp_module_t  ngx_tcp_lurk_module_ctx = {
    &ngx_tcp_lurk_protocol,                /* protocol */

    ngx_tcp_lurk_create_main_conf,         /* create main configuration */
    ngx_tcp_lurk_init_main_conf,           /* init main configuration */

    ngx_tcp_lurk_create_srv_conf,          /* create server configuration */
    ngx_tcp_lurk_merge_srv_conf            /* merge server configuration */
};


ngx_module_t  ngx_tcp_lurk_module = {
    NGX_MODULE_V1,
    &ngx_tcp_lurk_module_ctx,              /* module context */
    ngx_tcp_lurk_commands,                 /* module directives */
    NGX_TCP_MODULE,                        /* module type */
    NULL,                                  /* init master */
    ngx_tcp_lurk_init_module,              /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


ngx_tcp_log_var_t  ngx_tcp_lurk_vars[] = {
    { ngx_string("lurk_start_time"), NGX_TIME_T_LEN,
      ngx_tcp_lurk_get_start_time},

    { ngx_string("lurk_id"), NGX_INT_T_LEN,
      ngx_tcp_lurk_get_id},

    { ngx_string("lurk_pkey_id"), 64,
      ngx_tcp_lurk_get_pkey_id_hex},

    { ngx_string("lurk_sni"), 256,
      ngx_tcp_lurk_get_sni},

    { ngx_string("lurk_type"), NGX_INT_T_LEN,
      ngx_tcp_lurk_get_type},

    { ngx_string("lurk_client_ip"), NGX_SOCKADDR_STRLEN,
      ngx_tcp_lurk_get_client},

    { ngx_string("lurk_err_code"), NGX_INT_T_LEN,
      ngx_tcp_lurk_get_error},

    { ngx_null_string, 0, NULL }
};


static u_char *
ngx_tcp_lurk_get_start_time(ngx_tcp_session_t *s, u_char *buf,
    ngx_tcp_log_op_t *op)
{
    ngx_tcp_lurk_ctx_t  *ctx;

    ctx = ngx_tcp_get_module_ctx(s, ngx_tcp_lurk_module);

    return ngx_sprintf(buf, "%T", ctx->start_tv.tv_sec);
}


static u_char *
ngx_tcp_lurk_get_id(ngx_tcp_session_t *s, u_char *buf,
    ngx_tcp_log_op_t *op)
{
    ngx_tcp_lurk_ctx_t  *ctx;

    ctx = ngx_tcp_get_module_ctx(s, ngx_tcp_lurk_module);

    return ngx_sprintf(buf, "%ui", ctx->id);
}


static u_char *
ngx_tcp_lurk_get_pkey_id_hex(ngx_tcp_session_t *s, u_char *buf,
    ngx_tcp_log_op_t *op)
{
    ngx_tcp_lurk_ctx_t  *ctx;

    ctx = ngx_tcp_get_module_ctx(s, ngx_tcp_lurk_module);

    if (ctx->key_id.len > 0) {
        return  ngx_sprintf(buf, "%*s", 64, &ctx->key_id_hex);
    }

    return ngx_sprintf(buf, "-");
}


static u_char *
ngx_tcp_lurk_get_sni(ngx_tcp_session_t *s, u_char *buf,
    ngx_tcp_log_op_t *op)
{
    ngx_tcp_lurk_ctx_t  *ctx;

    ctx = ngx_tcp_get_module_ctx(s, ngx_tcp_lurk_module);

    if (ctx->servername.len > 256) {
        return  ngx_sprintf(buf, "%*s", 256, &ctx->servername.data);
    }

    return ngx_sprintf(buf, "%V", &ctx->servername);
}


static u_char *
ngx_tcp_lurk_get_type(ngx_tcp_session_t *s, u_char *buf,
    ngx_tcp_log_op_t *op)
{
    ngx_tcp_lurk_ctx_t  *ctx;

    ctx = ngx_tcp_get_module_ctx(s, ngx_tcp_lurk_module);

    return ngx_sprintf(buf, "%ui", ctx->type);
}


static u_char *
ngx_tcp_lurk_get_client(ngx_tcp_session_t *s, u_char *buf,
    ngx_tcp_log_op_t *op)
{
    ngx_tcp_lurk_ctx_t  *ctx;

    ctx = ngx_tcp_get_module_ctx(s, ngx_tcp_lurk_module);

    return ngx_sprintf(buf, "%V", &ctx->ip_text);
}


static u_char *
ngx_tcp_lurk_get_error(ngx_tcp_session_t *s, u_char *buf,
    ngx_tcp_log_op_t *op)
{
    ngx_tcp_lurk_ctx_t  *ctx;

    ctx = ngx_tcp_get_module_ctx(s, ngx_tcp_lurk_module);

    return ngx_sprintf(buf, "%ui", ctx->err);
}


static unsigned int
constant_time_msb(unsigned int a)
{
    return 0 - (a >> (sizeof(a) * 8 - 1));
}


static unsigned int
constant_time_is_zero(unsigned int a)
{
    return constant_time_msb(~a & (a - 1));
}


static unsigned char
constant_time_is_zero_8(unsigned int a)
{
    return (unsigned char)constant_time_is_zero(a);
}


static unsigned int
constant_time_eq(unsigned int a, unsigned int b)
{
    return constant_time_is_zero(a ^ b);
}


static unsigned char
constant_time_eq_8(unsigned int a, unsigned int b)
{
    return (unsigned char)constant_time_eq(a, b);
}


static unsigned char
constant_time_eq_int_8(int a, int b)
{
    return constant_time_eq_8((unsigned)(a), (unsigned)(b));
}


static unsigned int
constant_time_select(unsigned int mask, unsigned int a, unsigned int b)
{
    return (mask & a) | (~mask & b);
}


static unsigned char
constant_time_select_8(unsigned char mask, unsigned char a, unsigned char b)
{
    return (unsigned char)constant_time_select(mask, a, b);
}


static unsigned char *
ngx_tcp_lurk_rsa_pms_padding(unsigned char *rsa_decrypt,
    int decrypt_len, int client_version, int server_version)
{
    size_t         j, padding_len = 0;
    unsigned char  decrypt_good, version_good;
    unsigned char  rand_premaster_secret[SSL_MAX_MASTER_KEY_LENGTH];

    if (decrypt_len < 11 + SSL_MAX_MASTER_KEY_LENGTH) {
        return NULL;
    }

    if (RAND_bytes(rand_premaster_secret,
                   sizeof(rand_premaster_secret)) <= 0)
    {
        return NULL;
    }

    padding_len = decrypt_len - SSL_MAX_MASTER_KEY_LENGTH;
    decrypt_good = constant_time_eq_int_8(rsa_decrypt[0], 0) &
        constant_time_eq_int_8(rsa_decrypt[1], 2);
    for (j = 2; j < padding_len - 1; j++) {
        decrypt_good &= ~constant_time_is_zero_8(rsa_decrypt[j]);
    }

    decrypt_good &= constant_time_is_zero_8(rsa_decrypt[padding_len - 1]);

    version_good = constant_time_eq_8(rsa_decrypt[padding_len],
                                      (unsigned)(client_version >> 8));
    version_good &= constant_time_eq_8(rsa_decrypt[padding_len + 1],
                                       (unsigned)(client_version & 0xff));

    if (0) {
        unsigned char workaround_good;
        workaround_good = constant_time_eq_8(rsa_decrypt[padding_len],
                    (unsigned)(server_version >> 8));
        workaround_good &=
            constant_time_eq_8(rsa_decrypt[padding_len + 1],
                        (unsigned)(server_version & 0xff));
        version_good |= workaround_good;
    }

    decrypt_good &= version_good;

    for (j = 0; j < sizeof(rand_premaster_secret); j++) {
        rsa_decrypt[padding_len + j] =
            constant_time_select_8(decrypt_good,
                        rsa_decrypt[padding_len + j],
                        rand_premaster_secret[j]);
    }

    return rsa_decrypt + padding_len;
}


/* seed1 through seed5 are virtually concatenated */
ngx_int_t
ngx_tcp_lurk_tls1_p_hash(const EVP_MD *md, const unsigned char *sec,
   int sec_len, const void *seed1, int seed1_len,
   const void *seed2, int seed2_len, const void *seed3, int seed3_len,
   const void *seed4, int seed4_len, const void *seed5, int seed5_len,
   unsigned char *out, int olen)
{
    int             chunk;
    size_t          j;
    size_t          A1_len;
    EVP_PKEY       *mac_key = NULL;
    unsigned char   A1[EVP_MAX_MD_SIZE];
    ngx_int_t       ret = NGX_ERROR;

#if OPENSSL_VERSION_NUMBER >= 0x10100003L
    EVP_MD_CTX     *ctx = EVP_MD_CTX_new();
    EVP_MD_CTX     *ctx_tmp = EVP_MD_CTX_new();
    EVP_MD_CTX     *ctx_init = EVP_MD_CTX_new();
#else
    EVP_MD_CTX      md_ctx, md_ctx_tmp, md_ctx_init;
    EVP_MD_CTX     *ctx = &md_ctx;
    EVP_MD_CTX     *ctx_tmp = &md_ctx_tmp;
    EVP_MD_CTX     *ctx_init = &md_ctx_init;
#endif

    if (!ctx || !ctx_init || !ctx_tmp) {
        goto err;
    }

    chunk = EVP_MD_size(md);

    OPENSSL_assert(chunk >= 0);

    EVP_MD_CTX_init(ctx);
    EVP_MD_CTX_init(ctx_tmp);
    EVP_MD_CTX_init(ctx_init);
    EVP_MD_CTX_set_flags(ctx_init, EVP_MD_CTX_FLAG_NON_FIPS_ALLOW);

    mac_key = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, sec, sec_len);
    if (!mac_key) {
        goto err;
    }

    if (!EVP_DigestSignInit(ctx_init, NULL, md, NULL, mac_key)) {
        goto err;
    }

    if (!EVP_MD_CTX_copy_ex(ctx, ctx_init)) {
        goto err;
    }

    if (seed1 && !EVP_DigestSignUpdate(ctx, seed1, seed1_len)) {
        goto err;
    }

    if (seed2 && !EVP_DigestSignUpdate(ctx, seed2, seed2_len)) {
        goto err;
    }

    if (seed3 && !EVP_DigestSignUpdate(ctx, seed3, seed3_len)) {
        goto err;
    }

    if (seed4 && !EVP_DigestSignUpdate(ctx, seed4, seed4_len)) {
        goto err;
    }

    if (seed5 && !EVP_DigestSignUpdate(ctx, seed5, seed5_len)) {
        goto err;
    }

    if (!EVP_DigestSignFinal(ctx, A1, &A1_len)) {
        goto err;
    }

    for (;;) {
        /* Reinit mac contexts */
        if (!EVP_MD_CTX_copy_ex(ctx, ctx_init)) {
            goto err;
        }

        if (!EVP_DigestSignUpdate(ctx, A1, A1_len)) {
            goto err;
        }

        if (olen > chunk && !EVP_MD_CTX_copy_ex(ctx_tmp, ctx)) {
            goto err;
        }

        if (seed1 && !EVP_DigestSignUpdate(ctx, seed1, seed1_len)) {
            goto err;
        }

        if (seed2 && !EVP_DigestSignUpdate(ctx, seed2, seed2_len)) {
            goto err;
        }

        if (seed3 && !EVP_DigestSignUpdate(ctx, seed3, seed3_len)) {
            goto err;
        }

        if (seed4 && !EVP_DigestSignUpdate(ctx, seed4, seed4_len)) {
            goto err;
        }

        if (seed5 && !EVP_DigestSignUpdate(ctx, seed5, seed5_len)) {
            goto err;
        }

        if (olen > chunk) {
            if (!EVP_DigestSignFinal(ctx, out, &j)) {
                goto err;
            }

            out += j;
            olen -= j;
            /* calc the next A1 value */
            if (!EVP_DigestSignFinal(ctx_tmp, A1, &A1_len)) {
                goto err;
            }

        } else {                /* last one */

            if (!EVP_DigestSignFinal(ctx, A1, &A1_len)) {
                goto err;
            }

            memcpy(out, A1, olen);
            break;
        }
    }

    ret = NGX_OK;

 err:
    if (mac_key) {
        EVP_PKEY_free(mac_key);
    }

#if OPENSSL_VERSION_NUMBER >= 0x10100003L
    EVP_MD_CTX_free(ctx);
    EVP_MD_CTX_free(ctx_tmp);
    EVP_MD_CTX_free(ctx_init);
#else
    EVP_MD_CTX_cleanup(ctx);
    EVP_MD_CTX_cleanup(ctx_tmp);
    EVP_MD_CTX_cleanup(ctx_init);
#endif
    OPENSSL_cleanse(A1, sizeof(A1));

    return ret;
}

# define SSL_MD_MD5_IDX         0
# define SSL_MD_SHA1_IDX        1
# define SSL_MD_GOST94_IDX      2
# define SSL_MD_GOST89MAC_IDX   3
# define SSL_MD_SHA256_IDX      4
# define SSL_MD_SHA384_IDX      5
# define SSL_MD_GOST12_256_IDX  6
# define SSL_MD_GOST89MAC12_IDX 7
# define SSL_MD_GOST12_512_IDX  8
# define SSL_MD_MD5_SHA1_IDX    9
# define SSL_MD_SHA224_IDX     10
# define SSL_MD_SHA512_IDX     11
# define SSL_MAX_DIGEST        12

#if OPENSSL_VERSION_NUMBER < 0x10100003L


#define SSL_HANDSHAKE_MAC_MD5 0x10
#define SSL_HANDSHAKE_MAC_SHA 0x20
#define SSL_HANDSHAKE_MAC_GOST94 0x40
#define SSL_HANDSHAKE_MAC_SHA256 0x80
#define SSL_HANDSHAKE_MAC_SHA384 0x100
#define SSL_HANDSHAKE_MAC_MD5_SHA1 0x200
#define SSL_HANDSHAKE_MAC_SHA224 0x400
#define SSL_HANDSHAKE_MAC_SHA512 0x800

#define SSL_HANDSHAKE_MAC_DEFAULT (SSL_HANDSHAKE_MAC_MD5 | SSL_HANDSHAKE_MAC_SHA)


#else /* OPENSSL_VERSION_NUMBER */
/*
 * When adding new digest in the ssl_ciph.c and increment SSL_MD_NUM_IDX make
 * sure to update this constant too
 */

/* Bits for algorithm2 (handshake digests and other extra flags) */

/* Bits 0-7 are handshake MAC */
# define SSL_HANDSHAKE_MAC_MASK  0xFF
# define SSL_HANDSHAKE_MAC_MD5        0
# define SSL_HANDSHAKE_MAC_SHA        0
# define SSL_HANDSHAKE_MAC_MD5_SHA1   SSL_MD_MD5_SHA1_IDX
# define SSL_HANDSHAKE_MAC_SHA256     SSL_MD_SHA256_IDX
# define SSL_HANDSHAKE_MAC_SHA384     SSL_MD_SHA384_IDX
# define SSL_HANDSHAKE_MAC_GOST94     SSL_MD_GOST94_IDX
# define SSL_HANDSHAKE_MAC_GOST12_256 SSL_MD_GOST12_256_IDX
# define SSL_HANDSHAKE_MAC_GOST12_512 SSL_MD_GOST12_512_IDX
#define SSL_HANDSHAKE_MAC_SHA224      SSL_MD_SHA224_IDX
#define SSL_HANDSHAKE_MAC_SHA512      SSL_MD_SHA512_IDX

# define SSL_HANDSHAKE_MAC_DEFAULT    SSL_HANDSHAKE_MAC_MD5_SHA1

/* Bits 8-15 bits are PRF */
# define TLS1_PRF_DGST_SHIFT 8
# define TLS1_PRF_SHA1_MD5   (SSL_MD_MD5_SHA1_IDX << TLS1_PRF_DGST_SHIFT)
# define TLS1_PRF_SHA256     (SSL_MD_SHA256_IDX << TLS1_PRF_DGST_SHIFT)
# define TLS1_PRF_SHA384     (SSL_MD_SHA384_IDX << TLS1_PRF_DGST_SHIFT)
# define TLS1_PRF_GOST94     (SSL_MD_GOST94_IDX << TLS1_PRF_DGST_SHIFT)
# define TLS1_PRF_GOST12_256 (SSL_MD_GOST12_256_IDX << TLS1_PRF_DGST_SHIFT)
# define TLS1_PRF_GOST12_512 (SSL_MD_GOST12_512_IDX << TLS1_PRF_DGST_SHIFT)
# define TLS1_PRF            (SSL_MD_MD5_SHA1_IDX << TLS1_PRF_DGST_SHIFT)


#endif  /* OPENSSL_VERSION_NUMBER */


#define SSL_MD_NUM_IDX  SSL_MAX_DIGEST
static const EVP_MD *ssl_digest_methods[SSL_MD_NUM_IDX] = {
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
};

static int ssl_handshake_digest_flag[SSL_MD_NUM_IDX] = {
    SSL_HANDSHAKE_MAC_MD5, SSL_HANDSHAKE_MAC_SHA,
    SSL_HANDSHAKE_MAC_GOST94, 0, SSL_HANDSHAKE_MAC_SHA256,
    SSL_HANDSHAKE_MAC_SHA384, 0, 0, 0, SSL_HANDSHAKE_MAC_MD5_SHA1,
    SSL_HANDSHAKE_MAC_SHA224, SSL_HANDSHAKE_MAC_SHA512
};


void
ngx_tcp_lurk_load_ssl_method(void)
{
    ssl_digest_methods[SSL_MD_MD5_IDX] = EVP_get_digestbyname(SN_md5);
    OPENSSL_assert(EVP_MD_size(ssl_digest_methods[SSL_MD_MD5_IDX]) >= 0);

    ssl_digest_methods[SSL_MD_SHA1_IDX] = EVP_get_digestbyname(SN_sha1);
    OPENSSL_assert(EVP_MD_size(ssl_digest_methods[SSL_MD_SHA1_IDX]) >= 0);

    ssl_digest_methods[SSL_MD_GOST94_IDX] =
                                EVP_get_digestbyname(SN_id_GostR3411_94);
    ssl_digest_methods[SSL_MD_GOST89MAC_IDX] =
                                EVP_get_digestbyname(SN_id_Gost28147_89_MAC);

    ssl_digest_methods[SSL_MD_SHA256_IDX] = EVP_get_digestbyname(SN_sha256);
    ssl_digest_methods[SSL_MD_SHA384_IDX] = EVP_get_digestbyname(SN_sha384);

#if defined(NID_md5_sha1)
# if OPENSSL_VERSION_NUMBER >= 0x10100003L
    ssl_digest_methods[SSL_MD_MD5_SHA1_IDX] = EVP_md5_sha1();
# endif
#endif
#if defined(NID_sha224)
    ssl_digest_methods[SSL_MD_SHA224_IDX] = EVP_sha224();
#endif
#if defined(NID_sha512)
    ssl_digest_methods[SSL_MD_SHA512_IDX] = EVP_sha512();
#endif
}


static int
ssl_get_handshake_digest(int idx, long *mask, const EVP_MD **md)
{
    if (idx < 0 || idx >= SSL_MD_NUM_IDX) {
        return 0;
    }

    *mask = ssl_handshake_digest_flag[idx];
    if (*mask) {
      *md = ssl_digest_methods[idx];
    } else {
      *md = NULL;
    }

    return 1;
}


/* seed1 through seed5 are virtually concatenated */
int
ngx_tcp_lurk_tls1_prf(unsigned char *out, long digest_mask,
    const void *seed1, int seed1_len, const void *seed2, int seed2_len,
    const void *seed3, int seed3_len, const void *seed4, int seed4_len,
    const void *seed5, int seed5_len, const unsigned char *sec, int slen)
{
    int                   len, i, idx, count, olen;
    long                  m;
    const EVP_MD         *md;
    unsigned char        *out1;
    const unsigned char  *s1;
    unsigned char         buff[SSL_MAX_MASTER_KEY_LENGTH];

    out1 = &buff[0];
    olen = sizeof(buff);

    /* Count number of digests and partition sec evenly */
    count = 0;
    for (idx = 0; ssl_get_handshake_digest(idx, &m, &md); idx++) {
        if (m & digest_mask) {
            count++;
        }
    }

    if (!count) {
        /* Should never happen */
        SSLerr(SSL_F_TLS1_PRF, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    len = slen / count;
    if (count == 1) {
        slen = 0;
    }

    s1 = sec;
    memset(out, 0, olen);

    for (idx = 0; ssl_get_handshake_digest(idx, &m, &md); idx++) {
        if (m & digest_mask) {
            if (!md) {
                SSLerr(SSL_F_TLS1_PRF, SSL_R_UNSUPPORTED_DIGEST_TYPE);
                goto err;
            }

            if (ngx_tcp_lurk_tls1_p_hash(md, s1, len + (slen & 1),
                                         seed1, seed1_len, seed2, seed2_len,
                                         seed3, seed3_len, seed4, seed4_len,
                                         seed5, seed5_len, out1, olen)
                != NGX_OK)
            {
                goto err;
            }

            s1 += len;
            for (i = 0; i < olen; i++) {
                out[i] ^= out1[i];
            }
        }
    }

    return SSL3_MASTER_SECRET_SIZE;

 err:
    return 0;
}


#if OPENSSL_VERSION_NUMBER >= 0x10100003L
/* seed1 through seed5 are concatenated */
int ngx_tcp_lurk_tls1_prf_v2(long digest_mask,
                    const void *seed1, size_t seed1_len,
                    const void *seed2, size_t seed2_len,
                    const void *seed3, size_t seed3_len,
                    const void *seed4, size_t seed4_len,
                    const void *seed5, size_t seed5_len,
                    const unsigned char *sec, size_t slen,
                    unsigned char *out, size_t olen)
{
    const EVP_MD *md = NULL;
    EVP_PKEY_CTX *pctx = NULL;

    int   ret = 0;
    long  m;

    ssl_get_handshake_digest(digest_mask, &m, &md);
    if (md == NULL) {
        /* Should never happen */
        SSLerr(SSL_F_TLS1_PRF, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_TLS1_PRF, NULL);
    if (pctx == NULL || EVP_PKEY_derive_init(pctx) <= 0
        || EVP_PKEY_CTX_set_tls1_prf_md(pctx, md) <= 0
        || EVP_PKEY_CTX_set1_tls1_prf_secret(pctx, sec, (int)slen) <= 0)
        goto err;

    if (EVP_PKEY_CTX_add1_tls1_prf_seed(pctx, seed1, (int)seed1_len) <= 0)
        goto err;
    if (EVP_PKEY_CTX_add1_tls1_prf_seed(pctx, seed2, (int)seed2_len) <= 0)
        goto err;
    if (EVP_PKEY_CTX_add1_tls1_prf_seed(pctx, seed3, (int)seed3_len) <= 0)
        goto err;
    if (EVP_PKEY_CTX_add1_tls1_prf_seed(pctx, seed4, (int)seed4_len) <= 0)
        goto err;
    if (EVP_PKEY_CTX_add1_tls1_prf_seed(pctx, seed5, (int)seed5_len) <= 0)
        goto err;

    if (EVP_PKEY_derive(pctx, out, &olen) <= 0)
        goto err;
    ret = 1;

 err:
    EVP_PKEY_CTX_free(pctx);
    return ret;
}
#endif


int
ngx_tcp_lurk_ssl3_prf(unsigned char *out,
    const void *client_random, int client_random_len,
    const void *server_random, int server_random_len,
    const unsigned char *p, int len)
{
    static const unsigned char *salt[3] = {
#ifndef CHARSET_EBCDIC
        (const unsigned char *)"A",
        (const unsigned char *)"BB",
        (const unsigned char *)"CCC",
#else
        (const unsigned char *)"\x41",
        (const unsigned char *)"\x42\x42",
        (const unsigned char *)"\x43\x43\x43",
#endif
    };

    int               i, ret = 0;
    unsigned int      n;
    unsigned char     buf[EVP_MAX_MD_SIZE];

#if OPENSSL_VERSION_NUMBER >= 0x10100003L
    EVP_MD_CTX       *ctx = EVP_MD_CTX_new();
#else
    EVP_MD_CTX        md_ctx;
    EVP_MD_CTX       *ctx = &md_ctx;
#endif
    if (ctx == NULL)
        return ret;

    EVP_MD_CTX_init(ctx);
    for (i = 0; i < 3; i++) {
        if (EVP_DigestInit_ex(ctx, EVP_sha1(), NULL) <= 0 ||
            EVP_DigestUpdate(ctx, salt[i], strlen((const char *)salt[i])) <= 0 ||
            EVP_DigestUpdate(ctx, p, len) <= 0 ||
            EVP_DigestUpdate(ctx, client_random, client_random_len) <= 0 ||
            EVP_DigestUpdate(ctx, server_random, server_random_len) <= 0 ||
            EVP_DigestFinal_ex(ctx, buf, &n) <= 0 ||
            EVP_DigestInit_ex(ctx, EVP_md5(), NULL) <= 0 ||
            EVP_DigestUpdate(ctx, p, len) <= 0 ||
            EVP_DigestUpdate(ctx, buf, n) <= 0 ||
            EVP_DigestFinal_ex(ctx, out, &n) <= 0)
        {
            ret = 0;
            break;
        }
        out += n;
        ret += n;
    }

#if OPENSSL_VERSION_NUMBER >= 0x10100003L
    EVP_MD_CTX_free(ctx);
#else
    EVP_MD_CTX_cleanup(ctx);
#endif

    return ret;
}


ngx_int_t
ngx_tcp_lurk_prf(unsigned char *out, uint16_t version, long master_prf,
    const void *client_random, int client_random_len,
    const void *server_random, int server_random_len,
    const unsigned char *p, int len)
{
    int  rc;

    if (version == SSL3_VERSION) {
        rc = ngx_tcp_lurk_ssl3_prf(out, client_random, SSL3_RANDOM_SIZE,
                    server_random, SSL3_RANDOM_SIZE, p, len);
    } else {
#if OPENSSL_VERSION_NUMBER >= 0x10100003L
        rc = ngx_tcp_lurk_tls1_prf_v2(master_prf,
                 TLS_MD_MASTER_SECRET_CONST, TLS_MD_MASTER_SECRET_CONST_SIZE,
                 client_random, client_random_len, NULL, 0,
                 server_random, server_random_len, NULL, 0,
                 p, len, out, SSL3_MASTER_SECRET_SIZE);
#else
        rc = ngx_tcp_lurk_tls1_prf(out, master_prf,
                 TLS_MD_MASTER_SECRET_CONST, TLS_MD_MASTER_SECRET_CONST_SIZE,
                 client_random, client_random_len, NULL, 0,
                 server_random, server_random_len, NULL, 0, p, len);
#endif
    }

    return rc > 0 ? NGX_OK : NGX_ERROR;
}


static void
ngx_tcp_lurk_get_common_name(SSL *ssl, char *cn, size_t size)
{
    int               lastpos = -1;
    X509             *cert = NULL;
    X509_NAME        *subject = NULL;
    ASN1_STRING      *asn1_str = NULL;
    X509_NAME_ENTRY  *e = NULL;

    do {
        cert = SSL_get_peer_certificate(ssl);
        if (!cert) {
            break;
        }

        subject = X509_get_subject_name(cert);
        if (!subject) {
            break;
        }

        lastpos = X509_NAME_get_index_by_NID(subject, NID_commonName, lastpos);

        e = X509_NAME_get_entry(subject, lastpos);
        if (!e) {
            break;
        }

        asn1_str = X509_NAME_ENTRY_get_data(e);
        if (!asn1_str) {
            break;
        }

        ngx_memcpy(cn, ASN1_STRING_data(asn1_str),
                   ngx_min(size, (size_t)ASN1_STRING_length(asn1_str)));
    } while(0);

    if (cert) {
        X509_free(cert);
    }

    return;
}


#if OPENSSL_VERSION_NUMBER >= 0x10100003L
ngx_int_t ngx_tcp_lurk_prf_ems(unsigned char *out, uint16_t version,
    long master_prf, const void *client_random, int client_random_len,
    const void *server_random, int server_random_len,
    const void *session_hash, int hashlen,
    const unsigned char *p, int len)
{
    int  rc;

    if (version <= SSL3_VERSION) {
        rc = ngx_tcp_lurk_ssl3_prf(out, client_random, SSL3_RANDOM_SIZE,
                    server_random, SSL3_RANDOM_SIZE, p, len);
    } else if(version < TLS1_3_VERSION){
        rc = ngx_tcp_lurk_tls1_prf_v2(master_prf,
                TLS_MD_EXTENDED_MASTER_SECRET_CONST,
                TLS_MD_EXTENDED_MASTER_SECRET_CONST_SIZE,
                session_hash, hashlen,
                NULL, 0,
                NULL, 0,
                NULL, 0,
                p, len,
                out, SSL3_MASTER_SECRET_SIZE);
    } else {
        return NGX_ERROR;
    }

    return rc > 0 ? NGX_OK : NGX_ERROR;
}
#endif


static void
ngx_tcp_lurk_init_session(ngx_tcp_session_t *s)
{
    static ngx_int_t      ready = 0;
    ngx_connection_t     *c;
    ngx_tcp_lurk_ctx_t   *ctx;
    ngx_tcp_lurk_buf_t   *buf;
    ngx_tcp_lurk_conf_t  *lcf;
    char                  cn[65] = "";

    c = s->connection;

    c->log->action = "keyserver processing lurk init session";

    if (c->ssl) {
        ngx_tcp_lurk_get_common_name(c->ssl->connection, cn, sizeof(cn) - 1);
    }

    ngx_lurk_log_error(NGX_LOG_NOTICE, c->log, 0,
                       "init session, CN:%s", cn);

    lcf = ngx_tcp_get_module_srv_conf(s, ngx_tcp_lurk_module);

    // 非本地加载秘钥情况下, 即从远程keymanager拉取秘钥时,ready后才提供服务, 否则结束回话
    if (lcf->pkey_path.len == 0 && !ready) {
        ngx_lurk_log_error(NGX_LOG_ERR, c->log, 0, "keyserver not ready");
        ngx_tcp_lurk_finalize_session(s, 0);
        return;
    }

    if (s->buffer == NULL) {
        s->buffer = ngx_create_temp_buf(s->connection->pool, lcf->buffer_size);
        if (s->buffer == NULL) {
            ngx_tcp_lurk_finalize_session(s, 0);
            return;
        }
    } else {
        if (s->buffer->pos == NULL) {
            /* alloc memory for keepalive connection */
            s->buffer->start = ngx_palloc(s->connection->pool,
                                          lcf->buffer_size);
            if (s->buffer->start == NULL) {
                ngx_tcp_lurk_finalize_session(s, 0);
                return;
            }

            s->buffer->pos = s->buffer->start;
            s->buffer->last = s->buffer->start;
            s->buffer->end = s->buffer->last + lcf->buffer_size;
        }
    }

    s->out.len = 0;

    c->write->handler = ngx_tcp_lurk_write_handler;
    c->read->handler = ngx_tcp_lurk_read_handler;

    /* set module ctx to tcp session */
    ctx = ngx_tcp_get_module_ctx(s, ngx_tcp_lurk_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(s->connection->pool, sizeof(ngx_tcp_lurk_ctx_t));
        if (ctx == NULL) {
            ngx_tcp_lurk_finalize_session(s, 0);
            return;
        }

        ngx_tcp_set_ctx(s, ctx, ngx_tcp_lurk_module);

        (void) ngx_atomic_fetch_add(ngx_lurk_requests, 1);
        (void) ngx_atomic_fetch_add(ngx_lurk_accepts, 1);

    } else {
        /* reset ctx */
        buf = ctx->buf;

        if (lcf->pkey_path.len == 0 && ctx->evp_pkey) {
            EVP_PKEY_free(ctx->evp_pkey);
            ctx->evp_pkey = NULL;
        }

        ngx_memzero(ctx, sizeof(ngx_tcp_lurk_ctx_t));
        ctx->buf = buf;

        (void) ngx_atomic_fetch_add(ngx_lurk_requests, 1);
        (void) ngx_atomic_fetch_add(ngx_lurk_keepalives, 1);
    }

    ngx_str_set(&ctx->servername, "NULL");

    ngx_gettimeofday(&ctx->start_tv);

    ngx_queue_init(&ctx->http_body);

    if (s->keepalive_requests == 0) {
        s->keepalive_requests = lcf->keepalive_requests;
    }

    ngx_add_timer(c->read, lcf->read_timeout);

    /* read & process data */
    ngx_tcp_lurk_read(s);

    return;
}


static void
ngx_tcp_lurk_write_health(ngx_tcp_session_t *s)
{
    ngx_int_t             n;
    ngx_connection_t     *c;
    ngx_tcp_lurk_conf_t  *lcf;

    c = s->connection;

    c->log->action = "keyserver processing lurk write health";

    lcf = ngx_tcp_get_module_srv_conf(s, ngx_tcp_lurk_module);

    ngx_log_debug1(NGX_LOG_DEBUG_TCP, c->log, 0,
                   "[tcp lurk] write health: %d", c->fd);

    /* set data to s */
    s->out.data = (u_char *)NGX_TCP_LURK_HEALTH_RESP;
    s->out.len = NGX_TCP_LURK_HEALTH_RESP_L;

    /* write s->out to lurk client */
    n = c->send(c, s->out.data, s->out.len);

    if (n > 0) {
        s->out.data += n;
        s->out.len -= n;

        if (s->out.len != 0) {
            goto again;
        }

        if (c->write->timer_set) {
            ngx_del_timer(c->write);
        }

        ngx_tcp_lurk_finalize_session(s, 0);

        return;
    }

    if (n == NGX_ERROR) {
        ngx_lurk_log_error(NGX_LOG_ERR, c->log, ngx_socket_errno,
                           "write health fail");
        ngx_tcp_lurk_finalize_session(s, 0);
        return;
    }

    /* n == NGX_AGAIN */

again:

    ngx_add_timer(c->write, lcf->send_timeout);

    if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
        ngx_tcp_lurk_finalize_session(s, 0);
        return;
    }
}


static void
ngx_tcp_lurk_write_health_handler(ngx_event_t *wev)
{
    ngx_connection_t   *c;
    ngx_tcp_session_t  *s;

    c = wev->data;
    s = c->data;

    ngx_log_debug1(NGX_LOG_DEBUG_TCP, wev->log, 0,
                   "[tcp lurk] write health check handler: %d", c->fd);

    if (c->write->timedout) {
        c->write->timedout = 0;

        ngx_tcp_lurk_finalize_session(s, 0);
        return;
    }

    ngx_tcp_lurk_write_health(s);
}


static ngx_int_t
ngx_tcp_lurk_get_server_status(ngx_tcp_lurk_server_status_t *status)
{
    status->requests = *ngx_lurk_requests;
    status->fail_requests = *ngx_lurk_fail_requests;
    status->master_secret = *ngx_lurk_request_master_secret;
    status->sign = *ngx_lurk_request_sign;
    status->cert_verify = *ngx_lurk_request_cert_verify;
    status->pkey_rsa = *ngx_lurk_pkey_rsa;
    status->pkey_ecc = *ngx_lurk_pkey_ecc;
    status->no_key = *ngx_lurk_fail_no_key;
    status->bad_format = *ngx_lurk_fail_bad_format;
    status->bad_version = *ngx_lurk_fail_bad_version;
    status->bad_type = *ngx_lurk_fail_bad_type;
    status->fail_internal = *ngx_lurk_fail_internal;
    status->fail_decrypt = *ngx_lurk_fail_decrypt;
    status->fail_master_secret = *ngx_lurk_fail_master_secret;
    status->fail_sign = *ngx_lurk_fail_sign;
    status->fail_cert_verify = *ngx_lurk_fail_cert_verify;
    status->fail_write = *ngx_lurk_fail_write;
    status->fail_read = *ngx_lurk_fail_read;
    status->rtimeout = *ngx_lurk_fail_rtimeout;
    status->wtimeout = *ngx_lurk_fail_wtimeout;
    status->accepts = *ngx_lurk_accepts;
    status->keepalives = *ngx_lurk_keepalives;
    status->fail_unknown_msg = *ngx_lurk_fail_unknown_msg;

    if (status->requests > 0) {
        status->rt = *ngx_lurk_response_time / status->requests;
    } else {
        status->rt = 0;
    }

    return NGX_OK;
}


static void
ngx_tcp_lurk_write_status(ngx_tcp_session_t *s)
{
    ngx_int_t                      lurk_status_size;
    ngx_int_t                      n;
    ngx_buf_t                     *b;
    ngx_connection_t              *c;
    ngx_tcp_lurk_conf_t           *lcf;
    ngx_tcp_lurk_server_status_t   status;

    c = s->connection;

    c->log->action = "keyserver processing lurk write status";

    lcf = ngx_tcp_get_module_srv_conf(s, ngx_tcp_lurk_module);

    ngx_log_debug1(NGX_LOG_DEBUG_TCP, c->log, 0,
                   "[tcp lurk] write health: %d", c->fd);

    if (ngx_tcp_lurk_get_server_status(&status) != NGX_OK) {
        ngx_tcp_lurk_finalize_session(s, 0);
        return;
    }


    lurk_status_size = sizeof(NGX_TCP_LURK_STATUS_HEADER) + ngx_lurk_stat_count \
                                    + ngx_lurk_stat_count * NGX_ATOMIC_T_LEN;

    b = ngx_create_temp_buf(s->pool, lurk_status_size);
    if (b == NULL) {
        return;
    }

    b->last = ngx_cpymem(b->last, NGX_TCP_LURK_STATUS_HEADER,
                         sizeof(NGX_TCP_LURK_STATUS_HEADER) - 1);
    b->last = ngx_sprintf(b->last, "%-5uA %-5uA %-5uA %-5uA %-5uA %-5uA %-5uA %-5uA %-5uA %-5uA %-5uA %-5uA %-5uA %-5uA %-5uA %-5uA %-5uA"
                           " %-5uA %-5uA %-5uA %-5uA %-5uA %-5uA %-5uA\n", status.requests, status.accepts, status.keepalives,
                          status.fail_requests, status.master_secret,
                          status.sign, status.cert_verify, status.pkey_rsa, status.pkey_ecc,
                          status.rt, status.no_key, status.bad_version,
                          status.bad_format, status.bad_type, status.fail_internal,
                          status.fail_decrypt, status.fail_master_secret,
                          status.fail_sign, status.fail_cert_verify, status.fail_write, status.fail_read,
                          status.rtimeout, status.wtimeout, status.fail_unknown_msg);
    /* set data to s */
    s->out.data = b->pos;
    s->out.len = ngx_buf_size(b);

    /* write s->out to lurk client */
    n = c->send(c, s->out.data, s->out.len);

    if (n > 0) {
        s->out.data += n;
        s->out.len -= n;

        if (s->out.len != 0) {
            goto again;
        }

        if (c->write->timer_set) {
            ngx_del_timer(c->write);
        }

        ngx_tcp_lurk_finalize_session(s, 0);

        return;
    }

    if (n == NGX_ERROR) {
        ngx_lurk_log_error(NGX_LOG_ERR, c->log, ngx_socket_errno,
                           "write status fail");
        ngx_tcp_lurk_finalize_session(s, 0);
        return;
    }

    /* n == NGX_AGAIN */

again:

    ngx_add_timer(c->write, lcf->send_timeout);

    if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
        ngx_tcp_lurk_finalize_session(s, 0);
        return;
    }
}


static void
ngx_tcp_lurk_write_status_handler(ngx_event_t *wev)
{
    ngx_connection_t   *c;
    ngx_tcp_session_t  *s;

    c = wev->data;
    s = c->data;

    ngx_log_debug1(NGX_LOG_DEBUG_TCP, wev->log, 0,
                   "[tcp lurk] write status check handler: %d", c->fd);

    if (c->write->timedout) {
        c->write->timedout = 0;

        ngx_tcp_lurk_finalize_session(s, 0);
        return;
    }

    ngx_tcp_lurk_write_status(s);
}


static void
ngx_tcp_lurk_process_http_api(ngx_tcp_session_t *s)
{
    struct stat           stats;
    ngx_connection_t     *c;
    ngx_tcp_lurk_conf_t  *lcf;

    c = s->connection;
    lcf = ngx_tcp_get_module_srv_conf(s, ngx_tcp_lurk_module);

    c->log->action = "keyserver processing lurk http api";

    if (lcf->health_check.data) {
        ngx_lurk_log_error(NGX_LOG_NOTICE, c->log, 0,
                           "try health check");

        if (ngx_buf_size(s->buffer) < (off_t)NGX_TCP_LURK_HEALTH_REQ_L) {
            goto invalid;
        }

        if (ngx_strncmp(s->buffer->pos, NGX_TCP_LURK_HEALTH_REQ,
                        NGX_TCP_LURK_HEALTH_REQ_L) != 0)
        {
            goto invalid;
        }

        /* check if need to response or not */
        if (stat((char *)lcf->health_check.data, &stats) != 0) {
            ngx_lurk_log_error(NGX_LOG_ERR, c->log, 0,
                               "refuse lurk health check");
            ngx_tcp_lurk_finalize_session(s, 0);
            return;
        }

        /* assign PING as the opcode for health check */
        c->write->handler = ngx_tcp_lurk_write_health_handler;
        ngx_tcp_lurk_write_health(s);

    } else if (lcf->status_uri.data) {

        if (ngx_buf_size(s->buffer) < (off_t)lcf->status_req_line.len) {
            goto invalid;
        }

        if (ngx_strncmp(s->buffer->pos, lcf->status_req_line.data,
                        lcf->status_req_line.len) != 0)
        {
            goto invalid;
        }

        /* assign PING as the opcode for health check */
        c->write->handler = ngx_tcp_lurk_write_status_handler;
        ngx_tcp_lurk_write_status(s);

    } else {
invalid:
        ngx_lurk_log_error(NGX_LOG_ERR, c->log, 0,
                           "invalid lurk request data");

        (void) ngx_atomic_fetch_add(ngx_lurk_fail_unknown_msg, 1);
        ngx_tcp_lurk_finalize_session(s, 0);
    }
}


static void
ngx_tcp_lurk_reinit_connection(ngx_connection_t *c)
{
    ngx_tcp_session_t  *s;

    s = c->data;

    s->bytes_read = 0;
    s->bytes_write = 0;

    ngx_tcp_lurk_init_session(s);
}


static void
ngx_tcp_lurk_empty_handler(ngx_event_t *wev)
{
    ngx_log_debug0(NGX_LOG_DEBUG_TCP, wev->log, 0,
                   "[tcp lurk] empty handler");

    return;
}


static void
ngx_tcp_lurk_write_handler(ngx_event_t *wev)
{
    ngx_connection_t   *c;
    ngx_tcp_session_t  *s;

    c = wev->data;
    s = c->data;

    ngx_log_debug1(NGX_LOG_DEBUG_TCP, wev->log, 0,
                   "[tcp lurk] write handler: %d", c->fd);

    if (c->write->timedout) {
        c->write->timedout = 0;

        (void) ngx_atomic_fetch_add(ngx_lurk_fail_requests, 1);
        (void) ngx_atomic_fetch_add(ngx_lurk_fail_wtimeout, 1);

        ngx_tcp_lurk_finalize_session(s, 0);
        return;
    }

    ngx_tcp_lurk_write(s);
}


static void
ngx_tcp_lurk_read_handler(ngx_event_t *rev)
{
    ngx_connection_t   *c;
    ngx_tcp_session_t  *s;

    c = rev->data;
    s = c->data;

    ngx_log_debug1(NGX_LOG_DEBUG_TCP, rev->log, 0,
                   "[tcp lurk] read handler: %d", c->fd);

    if (c->read->timedout) {
        c->read->timedout = 0;
        (void) ngx_atomic_fetch_add(ngx_lurk_fail_requests, 1);
        (void) ngx_atomic_fetch_add(ngx_lurk_fail_rtimeout, 1);

        ngx_tcp_lurk_finalize_session(s, 0);
        return;
    }

    ngx_tcp_lurk_read(s);
}


static void
ngx_tcp_lurk_read(ngx_tcp_session_t *s)
{
    ssize_t               n;
    ngx_int_t             rc, ret;
    ngx_connection_t     *c;
    ngx_tcp_lurk_ctx_t   *ctx;
    ngx_tcp_lurk_conf_t  *lcf;

    lcf = ngx_tcp_get_module_srv_conf(s, ngx_tcp_lurk_module);

    c = s->connection;

    n = s->buffer->last - s->buffer->pos;

    c->log->action = "keyserver processing lurk read";

    ngx_log_debug2(NGX_LOG_DEBUG_TCP, c->log, 0,
                   "[tcp lurk] read: %d, have: %i", c->fd, n);

    ctx = ngx_tcp_get_module_ctx(s, ngx_tcp_lurk_module);

    if (n > 0) {
        /* data has been read in keepalive handler */
        goto process;
    }

    for (;;) {
        n = c->recv(c, s->buffer->last, s->buffer->end - s->buffer->last);

        if (n > 0) {
            s->buffer->last += n;

            ctx->in_process = 1;

process:
            rc = ngx_tcp_lurk_parse_request(s);

            if (rc == NGX_AGAIN) {
                continue;
            }


#if (NGX_DEBUG)

            ctx = ngx_tcp_get_module_ctx(s, ngx_tcp_lurk_module);

            ngx_log_debug3(NGX_LOG_DEBUG_TCP, c->log,
                           0, "lurk request: id: %ui, ip: %V, type: %ui",
                           ctx->id, &ctx->ip_text, ctx->type);
#endif

            if (rc == NGX_ERROR) {
                ngx_tcp_lurk_process_http_api(s);
                return;
            }

            /* rc == NGX_OK */
            break;
        }

        if (n == NGX_ERROR || n == 0) {
            if (ctx->in_process) {
                (void) ngx_atomic_fetch_add(ngx_lurk_fail_requests, 1);
                (void) ngx_atomic_fetch_add(ngx_lurk_fail_read, 1);
            }

            ngx_lurk_log_error(NGX_LOG_ERR, c->log, ngx_socket_errno,
                               "read fail n %d", n);
            ngx_tcp_lurk_finalize_session(s, 0);
            return;
        }

        if (n == NGX_AGAIN) {
            if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
                ngx_tcp_lurk_finalize_session(s, 0);
                return;
            }

            ngx_add_timer(c->read, lcf->read_timeout);

            return;
        }
    }

    ret = ngx_tcp_lurk_limit_keyid(s);
    if (ret == NGX_OK) {
        ret = ngx_tcp_lurk_process_request(s);
    }

    switch (ret) {
        case NGX_OK:
            ngx_tcp_lurk_write(s);

            break;
        case NGX_AGAIN:
            ctx->flag = NGX_TCP_LURK_FLAG_PROCESSING;
            break;
        case NGX_BUSY:
            ctx->flag = NGX_TCP_LURK_FLAG_RETRY;
            break;
        default:
            ngx_tcp_lurk_finalize_session(s, 0);
            break;
    }

    return;
}


static void
ngx_tcp_lurk_write(ngx_tcp_session_t *s)
{
    ngx_int_t             n;
    ngx_msec_int_t        ms;
    struct timeval        tv;
    ngx_atomic_int_t      temp_ms;
    ngx_connection_t     *c;
    ngx_tcp_lurk_ctx_t   *ctx;
    ngx_tcp_lurk_conf_t  *lcf;

    ctx = ngx_tcp_get_module_ctx(s, ngx_tcp_lurk_module);

    c = s->connection;

    c->log->action = "keyserver processing lurk write";

    lcf = ngx_tcp_get_module_srv_conf(s, ngx_tcp_lurk_module);

    ngx_log_debug1(NGX_LOG_DEBUG_TCP, c->log, 0, "keyserver tcp lurk write: %d", c->fd);

    /* write s->out to lurk client */
    n = c->send(c, s->out.data, s->out.len);

    if (n > 0) {
        s->out.data += n;
        s->out.len -= n;

        if (s->out.len != 0) {
            goto again;
        }

        if (c->write->timer_set) {
            ngx_del_timer(c->write);
        }

        /* len == 0 */
        /* len == 0 */
        ngx_gettimeofday(&tv);
        ms = (ngx_msec_int_t)
                ((tv.tv_sec - ctx->start_tv.tv_sec) * 1000
                + (tv.tv_usec - ctx->start_tv.tv_usec)) / 1000000;
        ms = ngx_max(ms, 0);
        temp_ms = (ngx_atomic_int_t)ms;
        (void) ngx_atomic_fetch_add(ngx_lurk_response_time, temp_ms);
        ngx_tcp_lurk_finalize_session(s, 1);

        return;
    }

    if (n == NGX_ERROR) {
        ngx_lurk_log_error(NGX_LOG_ERR, c->log, ngx_socket_errno, "send fail");
        ngx_tcp_lurk_finalize_session(s, 0);
        return;
    }

    /* n == NGX_AGAIN */

again:

    ngx_add_timer(c->write, lcf->send_timeout);

    if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
        ngx_tcp_lurk_finalize_session(s, 0);
        return;
    }
}


static ngx_int_t
ngx_tcp_lurk_parse_request(ngx_tcp_session_t *s)
{
    size_t                    blen, plen;
    ngx_tcp_lurk_ctx_t       *ctx;
    ngx_lurk_proto_item_t    *item;
    ngx_lurk_key_pair_id_t   *key_id;
    ngx_lurk_query_header_t  *header;

#if (NGX_HAVE_INET6)
    unsigned char            *client_ipv6;
#endif
    u_char                    text[NGX_SOCKADDR_STRLEN];

    enum {
        sw_start = 0,
        sw_header,
        sw_header_post,
        sw_payload,
        sw_done,
    } state;

    s->connection->log->action = "keyserver processing lurk parse request";

    /* parse request, save parsed data into s->ctx[lurk] */

    ctx = ngx_tcp_get_module_ctx(s, ngx_tcp_lurk_module);

    for (;;) {

        state = ctx->state;

        switch (state) {
        case sw_start:

            blen = s->buffer->last - s->buffer->pos;
            if (blen < sizeof(*header)) {
                return NGX_AGAIN;
            }

            ctx->state = sw_header;
            break;

        case sw_header:

            header = (ngx_lurk_query_header_t *)s->buffer->pos;

            ctx->header = header;

            if ((header->qrv & 0x80) != (NGX_LURK_QUERY_BIT_QUERY << 7)) {
                ngx_lurk_log_error(NGX_LOG_ERR, s->connection->log, 0,
                                   "invalid lurk request query header %xi", header->qrv);
                ctx->err = NGX_LURK_RESPONSE_UNVALID_QUERY_TYPE;
                (void) ngx_atomic_fetch_add(ngx_lurk_fail_bad_format, 1);
                return NGX_ERROR;
            }

            ctx->version = (header->qrv & 0x07);
            if (ctx->version < NGX_LURK_VERSION_MIN || ctx->version > NGX_LURK_VERSION_MAX) {
                ngx_lurk_log_error(NGX_LOG_ERR, s->connection->log, 0,
                                   "invalid lurk request version %d", ctx->version);
                ctx->err = NGX_LURK_RESPONSE_UNVALID_LURK_VERSION;
                (void) ngx_atomic_fetch_add(ngx_lurk_fail_bad_version, 1);
                return NGX_ERROR;
            }

            ctx->type = header->type;
            ctx->id = ntohll(header->id);

            switch (ctx->type) {
            case NGX_LURK_QUERY_TYPE_PING:
            case NGX_LURK_QUERY_TYPE_CAP:
            case NGX_LURK_QUERY_TYPE_RSA_MASTER:
            case NGX_LURK_QUERY_TYPE_RSA_EXTENDED_MASTER:
            case NGX_LURK_QUERY_TYPE_PFS_RSA_MASTER:
            case NGX_LURK_QUERY_TYPE_ECDHE:
            case NGX_LURK_QUERY_TYPE_PFS_NON_PREDICTABLE_ECDHE:
#if OPENSSL_VERSION_NUMBER >= 0x10100003L
            case NGX_LURK_QUERY_TYPE_CERT_VERIFY:
#endif
                break;
            default:
                (void) ngx_atomic_fetch_add(ngx_lurk_fail_bad_type, 1);
                ctx->err = NGX_LURK_RESPONSE_UNVALID_QUERY_TYPE;
                ngx_lurk_log_error(NGX_LOG_ERR, s->connection->log, 0,
                                   "invalid query type: %xi", ctx->type);
                return NGX_ERROR;
            }

            ctx->state = sw_header_post;
            break;

       case sw_header_post:

            header = (ngx_lurk_query_header_t *)s->buffer->pos;
            blen = s->buffer->last - s->buffer->pos;

            if (blen < (sizeof(*header) + sizeof(uint16_t))) {
                return NGX_AGAIN;
            }

            plen = ntohs(*(uint16_t *)(header + 1));

            if (blen - sizeof(*header) < plen) {
                return NGX_AGAIN;
            }

            ctx->payload.start = (u_char *)(header + 1);
            ctx->payload.pos = ctx->payload.start;
            ctx->payload.last = ctx->payload.pos;
            ctx->payload.end = ctx->payload.start + plen;

            ctx->state = sw_payload;
            break;

        case sw_payload:

            header = (ngx_lurk_query_header_t *)s->buffer->pos;

            key_id = (ngx_lurk_key_pair_id_t *)((u_char *)(header + 1)
                                                           + sizeof(uint16_t));

            if (key_id->type != NGX_LURK_KEY_PAIR_ID_TYPE_SHA256
                || key_id->data.length != NGX_LURK_KEY_PAIR_ID_SHA256_LEN)
            {
                ctx->err = NGX_LURK_RESPONSE_UNVALID_KEY_PAIR_ID_FORMAT;
                ngx_lurk_log_error(NGX_LOG_ERR, s->connection->log, 0,
                                   "invalid query key pair id format: %d",
                                   key_id->type);
                (void) ngx_atomic_fetch_add(ngx_lurk_fail_bad_format, 1);
                return NGX_ERROR;
            }

            ctx->key_id.len = NGX_LURK_KEY_PAIR_ID_SHA256_LEN;
            ctx->key_id.data = key_id->data.value;

            ngx_hex_dump(&ctx->key_id_hex[0], ctx->key_id.data, ctx->key_id.len);

            ngx_log_debug4(NGX_LOG_DEBUG_EVENT, s->connection->log,
                           0, "[tcp lurk] payload length: %ui, type: %d, key_id: %*s",
                           ngx_buf_size((&ctx->payload)), ctx->type,
                           64, &ctx->key_id_hex);

            ctx->payload.last += sizeof(uint16_t) + sizeof(ngx_lurk_key_pair_id_t)
                                + ctx->key_id.len;

            if (ctx->version >= NGX_LURK_V3) {
                item = (ngx_lurk_proto_item_t *)ctx->payload.last;
                if (item->tag == NGX_LURK_PROTO_TAG_SNI) {
                    ctx->servername.len = ntohs(item->length);
                    ctx->servername.data = ngx_pcalloc(s->connection->pool,
                                                       ctx->servername.len);
                    if (ctx->servername.data == NULL) {
                        ngx_lurk_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
                                           "servername ngx_pcalloc failed");

                        ctx->err = NGX_LURK_RESPONSE_ERROR_INTERNAL;
                        return NGX_ERROR;
                    }

                    ngx_memcpy(ctx->servername.data,
                               ctx->payload.last + sizeof(*item),
                               ctx->servername.len);

                    ctx->payload.last += sizeof(*item) + ctx->servername.len;
                }

                item = (ngx_lurk_proto_item_t *)ctx->payload.last;
                if (item->tag == NGX_LURK_PROTO_TAG_CLIENT_IP) {
                    if (ntohs(item->length) != 4) {
                        ngx_lurk_log_error(NGX_LOG_ERR, s->connection->log, 0,
                                           "[sni:%V] invalid lurk proto item client ip "
                                           "length: %d", &ctx->servername,
                                           ntohs(item->length));
                        (void) ngx_atomic_fetch_add(ngx_lurk_fail_bad_format, 1);
                        return NGX_ERROR;
                    }
                    ctx->client_ip = ntohl(*(uint32_t *)(item + 1));
                    ctx->payload.last += sizeof(*item) + 4;

                    ctx->ip_text.len = ngx_inet_ntop(AF_INET,
                                                     &ctx->client_ip,
                                                     text,
                                                     NGX_SOCKADDR_STRLEN);
                    ctx->ip_text.data = ngx_pcalloc(s->connection->pool,
                                                    ctx->ip_text.len);
                    ngx_memcpy(ctx->ip_text.data, text, ctx->ip_text.len);
                }
#if (NGX_HAVE_INET6)
                else if (item->tag == NGX_LURK_PROTO_TAG_CLIENT_IPV6) {
                    if (ntohs(item->length) != sizeof(struct in6_addr)) {
                        ngx_lurk_log_error(NGX_LOG_ERR, s->connection->log, 0,
                                           "[sni:%V] invalid lurk proto item client ipv6 "
                                           "length: %d", &ctx->servername,
                                           ntohs(item->length));
                        (void) ngx_atomic_fetch_add(ngx_lurk_fail_bad_format, 1);
                        return NGX_ERROR;
                    }
                    client_ipv6 = (unsigned char*)(item + 1);
                    ngx_memcpy(ctx->client_ipv6, client_ipv6, sizeof(struct in6_addr));
                    ctx->payload.last += sizeof(*item) + sizeof(struct in6_addr);

                    ctx->ip_text.len = ngx_inet_ntop(AF_INET6,
                                                     client_ipv6,
                                                     text, NGX_SOCKADDR_STRLEN);
                    ctx->ip_text.data = ngx_pcalloc(s->connection->pool,
                                                    ctx->ip_text.len);
                    ngx_memcpy(ctx->ip_text.data, text, ctx->ip_text.len);
                }
#endif
            }
            if (ctx->version == NGX_LURK_V4) {
                item = (ngx_lurk_proto_item_t *)ctx->payload.last;
                if (item->tag == NGX_LURK_PROTO_TAG_KEY) {
                    ctx->payload.last += sizeof(*item);
                    ctx->private_key_str.data = ctx->payload.last;
                    ctx->private_key_str.len = ntohs(item->length);
                    ctx->payload.last += ntohs(item->length);
                }
            }

            ctx->state = sw_done;
            break;

        case sw_done:
            return NGX_OK;

        default:
            ctx->err = NGX_LURK_RESPONSE_ERROR_INTERNAL;
            return NGX_ERROR;
        }
    }

    ctx->err = NGX_LURK_RESPONSE_ERROR_INTERNAL;
    return NGX_ERROR;
}


static ngx_int_t
ngx_tcp_lurk_get_pkey_id(EVP_PKEY *pkey, uint8_t *key_id)
{
    char            *hex;
    RSA             *rsa;
    EC_KEY          *ec_key;
    const EC_POINT  *ec_pub_key;
    const EC_GROUP  *group;
    const BIGNUM    *n = NULL;

    if (pkey == NULL || key_id == NULL) {
        return NGX_ERROR;
    }

#if OPENSSL_VERSION_NUMBER >= 0x10100003L
    switch (EVP_PKEY_id(pkey)) {
#else
    switch (pkey->type) {
#endif
    case EVP_PKEY_RSA:
        rsa = EVP_PKEY_get1_RSA(pkey);
        if (rsa == NULL) {
            return NGX_ERROR;
        }

#if OPENSSL_VERSION_NUMBER >= 0x10100003L
        RSA_get0_key(rsa, &n, NULL, NULL);
#else
        n = rsa->n;
#endif
        hex = BN_bn2hex(n);

        break;
    case EVP_PKEY_EC:
        ec_key = EVP_PKEY_get1_EC_KEY(pkey);
        if (ec_key == NULL) {
            return NGX_ERROR;
        }

        ec_pub_key = EC_KEY_get0_public_key(ec_key);
        if (ec_pub_key == NULL) {
            return NGX_ERROR;
        }

        group = EC_KEY_get0_group(ec_key);
        if (group == NULL) {
            return NGX_ERROR;
        }

        hex = EC_POINT_point2hex(group, ec_pub_key,
                                 EC_KEY_get_conv_form(ec_key), NULL);

        break;
    default:
        return NGX_ERROR;
    }

    if (hex == NULL) {
        return NGX_ERROR;
    }

    EVP_MD_CTX *ctx = EVP_MD_CTX_create();
    EVP_DigestInit_ex(ctx, EVP_sha256(), 0);
    EVP_DigestUpdate(ctx, hex, ngx_strlen(hex));
    EVP_DigestFinal_ex(ctx, key_id, 0);
    EVP_MD_CTX_destroy(ctx);

    OPENSSL_free(hex);

    return NGX_OK;
}


static EVP_PKEY *
ngx_tcp_lurk_find_pkey(ngx_tcp_session_t *s, uint8_t *key_id)
{
    EVP_PKEY                 *pkey = NULL;
    ngx_int_t                 rc;
    ngx_uint_t                hash;
    ngx_rbtree_node_t        *node, *sentinel;
    ngx_tcp_lurk_conf_t      *lcf;
    ngx_tcp_lurk_key_node_t  *pn, *target = NULL;

    lcf = ngx_tcp_get_module_srv_conf(s, ngx_tcp_lurk_module);

    hash = ngx_crc32_short(key_id, NGX_TCP_LURK_KEY_ID_LEN);

    s->connection->log->action = "keyserver processing lurk find pkey";

    node = lcf->pkey_tree.root;
    sentinel = lcf->pkey_tree.sentinel;

    while (node != sentinel) {

        if (hash < node->key) {
            node = node->left;
            continue;
        }

        if (hash > node->key) {
            node = node->right;
            continue;
        }

        /* hash == node->key */

        pn = (ngx_tcp_lurk_key_node_t *) node;

        /* TODO: optimize this */
        rc = ngx_memcmp(key_id, pn->key_id, NGX_TCP_LURK_KEY_ID_LEN);

        if (rc == 0) {
            ngx_log_debug1(NGX_LOG_DEBUG_TCP, s->connection->log, 0,
                           "[tcp lurk] keyserver found key, %ui", pn->node.key);
            target = pn;
            break;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    if (target) {
        pkey = target->pkey;
    }

    return pkey;
}


static ngx_int_t
ngx_tcp_lurk_buf_init(ngx_tcp_session_t *s)
{
    ngx_int_t            blen = 0;
    ngx_tcp_lurk_ctx_t  *ctx;
    ngx_tcp_lurk_buf_t  *buf;

    ctx = ngx_tcp_get_module_ctx(s, ngx_tcp_lurk_module);

#if OPENSSL_VERSION_NUMBER >= 0x10100003L
    ctx->pkey_size = EVP_PKEY_size(ctx->evp_pkey);
#else
    if (ctx->evp_pkey->type == EVP_PKEY_RSA) {
        ctx->pkey_size = RSA_size(ctx->evp_pkey->pkey.rsa);
    } else if (ctx->evp_pkey->type == EVP_PKEY_EC) {
        ctx->pkey_size = ECDSA_size(ctx->evp_pkey->pkey.ec);
    }
#endif

    buf = ctx->buf;

    blen = sizeof(ngx_tcp_lurk_buf_t) + sizeof(ngx_lurk_response_header_t)
            + ctx->pkey_size + SSL3_RANDOM_SIZE;

    if (buf == NULL || blen > ctx->buf_len) {
        buf = ngx_pcalloc(s->pool, blen);
        if (buf == NULL) {
            return NGX_ERROR;
        }
    }

    buf->buf.start = (u_char *)buf + sizeof(ngx_tcp_lurk_buf_t);
    buf->buf.pos = buf->buf.start;
    buf->buf.last = buf->buf.pos;
    buf->buf.end = (u_char *)buf + blen;

    buf->header.start = buf->buf.start;
    buf->header.pos = buf->buf.pos;
    buf->header.last = buf->buf.last;
    buf->header.end = buf->header.start + sizeof(ngx_lurk_response_header_t);

    buf->body.start = buf->header.end;
    buf->body.pos = buf->body.start;
    buf->body.last = buf->body.pos;
    buf->body.end = buf->buf.end;

    ctx->buf = buf;
    ctx->buf_len = blen;

    return NGX_OK;
}


static ngx_int_t
ngx_tcp_lurk_rsa_master(ngx_tcp_session_t *s)
{
    long                                      master_prf;
    int                                       error = 0;
    size_t                                    i;
    BN_CTX                                   *bn_ctx;
    ngx_str_t                                 key_str;
    EC_POINT                                 *ec_point;
    EVP_PKEY                                 *pkey;
    ngx_int_t                                 ret, len, pkey_type, field_size;
    ngx_str_t                                 decrypt_res, enpms, enc_str;
    ngx_buf_t                                *master_secret;
    unsigned char                            *ms_padding;
    ngx_str_t                                 private_key_str;
    const EC_GROUP                           *group;
    ngx_tcp_lurk_ctx_t                       *ctx;
    ngx_lurk_tls_master_rsa_input_payload_t  *rsa;

    rsa = NULL;
    s->connection->log->action = "keyserver processing lurk rsa master";

    ngx_log_debug0(NGX_LOG_DEBUG_TCP, s->connection->log, 0,
                   "[tcp lurk] keyserver lurk rsa master");

    ctx = ngx_tcp_get_module_ctx(s, ngx_tcp_lurk_module);

    if (ctx->version < NGX_LURK_V4) {
        rsa = (ngx_lurk_tls_master_rsa_input_payload_t *)ctx->payload.last;

        rsa->client_version = ntohs(rsa->client_version);
        rsa->edge_server_version = ntohs(rsa->edge_server_version);
        rsa->encryped_pre_master_secret.length =
                                    ntohs(rsa->encryped_pre_master_secret.length);
    }

    if (rsa == NULL) {
        ngx_lurk_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
                           "[sni:%V] rsa input payload is null", &ctx->servername);
        return NGX_ERROR;
    }

    for (i = 0; i < sizeof(ctx->dec_key); i++) {
        ctx->dec_key[i] = rsa->client_random[i] ^ rsa->edge_server_random[i];
        ctx->enc_key[i] = ctx->dec_key[i];
        ctx->dec_key[i] = ctx->dec_key[i] ^ (uint8_t)(rsa->edge_server_version>>(i%2));
        ctx->enc_key[i] = ctx->enc_key[i] ^ rsa->edge_server_random[0];
        key_str.data = ctx->dec_key;
        key_str.len = sizeof(ctx->dec_key);
    }

    if (ctx->version == NGX_LURK_V4) {
        private_key_str = ctx->private_key_str;
        (void)ngx_ssl_lurk_decrypt(&key_str, &private_key_str, &private_key_str);
        ctx->evp_pkey = d2i_AutoPrivateKey(&ctx->evp_pkey, (const unsigned char **)&private_key_str.data, private_key_str.len);
        if (ctx->evp_pkey == NULL) {
            ngx_lurk_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
                               "[sni:%V] pkey load client key failed", &ctx->servername);
        }
    }

    switch (rsa->master_prf) {
    case NGX_LURK_TLS_PRF_SHA256:
        master_prf = SSL_HANDSHAKE_MAC_SHA256;
        break;
    case NGX_LURK_TLS_PRF_SHA384:
        master_prf = SSL_HANDSHAKE_MAC_SHA384;
        break;
    case NGX_LURK_TLS_PRF_MD5SHA1:
        master_prf = SSL_HANDSHAKE_MAC_DEFAULT;
        break;
    default:
        ctx->err = NGX_LURK_RESPONSE_UNVALID_PRF;
        (void) ngx_atomic_fetch_add(ngx_lurk_fail_master_secret, 1);
        ngx_lurk_log_error(NGX_LOG_ERR, s->connection->log, 0,
                           "[sni:%V][client_ip:%V]invalid master prf %d",
                           &ctx->servername, &ctx->ip_text, rsa->master_prf);
        return NGX_ERROR;
    }

    enpms.len = rsa->encryped_pre_master_secret.length;
    enpms.data = (u_char *)&rsa->encryped_pre_master_secret.value;

    if (&rsa->encryped_pre_master_secret.value[0] + enpms.len
        != ctx->payload.end)
    {
        ctx->err = NGX_LURK_RESPONSE_UNVALID_ENCRYPTED_MASTER_LENGTH;
        (void) ngx_atomic_fetch_add(ngx_lurk_fail_master_secret, 1);
        ngx_lurk_log_error(NGX_LOG_ERR, s->connection->log, 0,
                           "[sni:%V][client_ip:%V]invalid master length %d",
                           &ctx->servername, &ctx->ip_text, enpms.len);
        return NGX_ERROR;
    }

    if (ctx->version >= NGX_LURK_V2) {
        (void)ngx_ssl_lurk_decrypt(&key_str, &enpms, &enpms);
    }

    ctx->master_prf = master_prf;
    ctx->rsa = rsa;
#if OPENSSL_VERSION_NUMBER >= 0x10100003L
    ctx->ems_rsa = NULL;
#endif

    pkey = ctx->evp_pkey;

    if (pkey == NULL) {
        ngx_lurk_log_error(NGX_LOG_ERR, s->connection->log, 0,
                           "[sni:%V][client_ip:%V]rsa master find no key",
                           &ctx->servername, &ctx->ip_text);
        ctx->err = NGX_LURK_RESPONSE_UNVALID_KEY_PAIR_ID;
        (void) ngx_atomic_fetch_add(ngx_lurk_fail_no_key, 1);

        return NGX_ERROR;
    }

    decrypt_res.data = ngx_palloc(s->pool, ctx->pkey_size);
    if (decrypt_res.data == NULL) {
        ctx->err = NGX_LURK_RESPONSE_ERROR_INTERNAL;
        ngx_lurk_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
                           "[sni:%V][client_ip:%V]rsa master palloc fail",
                           &ctx->servername, &ctx->ip_text);
        (void) ngx_atomic_fetch_add(ngx_lurk_fail_internal, 1);

        return NGX_ERROR;
    }

    ctx->decrypt_res.data = decrypt_res.data;

    (void) ngx_atomic_fetch_add(ngx_lurk_request_master_secret, 1);

#if OPENSSL_VERSION_NUMBER >= 0x10100003L
    pkey_type = EVP_PKEY_id(pkey);
#else
    pkey_type = pkey->type;
#endif
    if (pkey_type == EVP_PKEY_RSA) {
        ret = RSA_private_decrypt(enpms.len, enpms.data, decrypt_res.data,
#if OPENSSL_VERSION_NUMBER >= 0x10100003L
                                  EVP_PKEY_get0_RSA(pkey),
#else
                                  pkey->pkey.rsa,
#endif
                                  RSA_NO_PADDING);

        if (ret == -1 || ret > ctx->pkey_size) {
            error = ERR_get_error();
            ngx_lurk_log_error(NGX_LOG_ERR, s->connection->log, 0,
                               "[sni:%V][client_ip:%V]rsa master decrypt fail, ret %d error %d",
                               &ctx->servername, &ctx->ip_text, ret, ERR_GET_REASON(error));
            (void) ngx_atomic_fetch_add(ngx_lurk_fail_decrypt, 1);
            ctx->err = NGX_LURK_RESPONSE_ERROR_INTERNAL;
            return NGX_ERROR;
        }

        ms_padding = ngx_tcp_lurk_rsa_pms_padding(decrypt_res.data, ret,
                                                  rsa->client_version,
                                                  rsa->edge_server_version);
        if (ms_padding == NULL) {
            ctx->err = NGX_LURK_RESPONSE_ERROR_INTERNAL;
            ngx_lurk_log_error(NGX_LOG_ERR, s->connection->log, 0,
                               "[sni:%V][client_ip:%V]rsa master padding fail",
                               &ctx->servername, &ctx->ip_text);
            (void) ngx_atomic_fetch_add(ngx_lurk_fail_master_secret, 1);
            return NGX_ERROR;
        }

        len = SSL_MAX_MASTER_KEY_LENGTH;

        decrypt_res.data = ms_padding;

        (void) ngx_atomic_fetch_add(ngx_lurk_pkey_rsa, 1);

    } else if (pkey_type == EVP_PKEY_EC) {
#if OPENSSL_VERSION_NUMBER >= 0x10100003L
        EC_KEY *ec = EVP_PKEY_get0_EC_KEY(pkey);
        group = EC_KEY_get0_group(ec);
#else
        group = EC_KEY_get0_group(pkey->pkey.ec);
#endif

        ec_point = EC_POINT_new(group);
        if (ec_point == NULL) {
            ctx->err = NGX_LURK_RESPONSE_ERROR_INTERNAL;
            return NGX_ERROR;
        }

        bn_ctx = BN_CTX_new();
        if (bn_ctx == NULL) {
            EC_POINT_free(ec_point);
            ctx->err = NGX_LURK_RESPONSE_ERROR_INTERNAL;
            return NGX_ERROR;
        }

        if (EC_POINT_oct2point(group, ec_point, enpms.data, enpms.len,
                               bn_ctx) == 0)
        {
            EC_POINT_free(ec_point);
            BN_CTX_free(bn_ctx);
            ctx->err = NGX_LURK_RESPONSE_ERROR_INTERNAL;
            return NGX_ERROR;
        }

        field_size = EC_GROUP_get_degree(group);

#if OPENSSL_VERSION_NUMBER >= 0x10100003L
        ret = ECDH_compute_key(decrypt_res.data, (field_size+7)/8, ec_point, ec, NULL);
#else
        ret = ECDH_compute_key(decrypt_res.data, (field_size+7)/8, ec_point, pkey->pkey.ec, NULL);
#endif
        EC_POINT_free(ec_point);
        BN_CTX_free(bn_ctx);

        if (ret != -1) {
            len = ret;
        } else {
            /* TODO: set to KSSL_ERROR_CRYPTO_FAILED if
             * err == ERR_R_MALLOC_FAILURE or
             * err == ERR_R_INTERNAL_ERROR
             */
            int error = 0;
            error = ERR_get_error();
            ctx->err = NGX_LURK_RESPONSE_ERROR_INTERNAL;
            ngx_lurk_log_error(NGX_LOG_ERR, s->connection->log, 0,
                               "[sni:%V][client_ip:%V]rsa master compute key fail, ret %d error %d",
                               &ctx->servername, &ctx->ip_text, ret, ERR_GET_REASON(error));
            ERR_clear_error();
            (void) ngx_atomic_fetch_add(ngx_lurk_fail_decrypt, 1);
            return NGX_ERROR;
        }

        (void) ngx_atomic_fetch_add(ngx_lurk_pkey_ecc, 1);

    } else {
        ctx->err = NGX_LURK_RESPONSE_ERROR_INTERNAL;
        return NGX_ERROR;
    }

    master_secret = &ctx->buf->body;

    if (ngx_tcp_lurk_prf(master_secret->pos, rsa->edge_server_version,
                    master_prf, &rsa->client_random[0], SSL3_RANDOM_SIZE,
                    &rsa->edge_server_random[0], SSL3_RANDOM_SIZE,
                    decrypt_res.data, len) != NGX_OK)
    {
        ngx_lurk_log_error(NGX_LOG_ERR, s->connection->log, 0,
                           "[sni:%V][client_ip:%V]rsa master prf fail",
                           &ctx->servername, &ctx->ip_text);
        ctx->err = NGX_LURK_RESPONSE_ERROR_INTERNAL;
        (void) ngx_atomic_fetch_add(ngx_lurk_fail_master_secret, 1);
        return NGX_ERROR;
    }

    if (ctx->version >= NGX_LURK_V2) {
        key_str.data = ctx->enc_key;
        key_str.len = sizeof(ctx->enc_key);

        enc_str.data = master_secret->pos;
        enc_str.len = SSL3_MASTER_SECRET_SIZE;

        (void)ngx_ssl_lurk_encrypt(&key_str, &enc_str, &enc_str);
    }

    master_secret->last += SSL3_MASTER_SECRET_SIZE;

    return NGX_OK;
}


#if OPENSSL_VERSION_NUMBER >= 0x10100003L
static ngx_int_t
ngx_tcp_lurk_rsa_extended_master(ngx_tcp_session_t *s)
{
    long                                        master_prf;
    int                                         error = 0;
    unsigned int                               i;
    BN_CTX                                     *bn_ctx;
    EC_POINT                                   *ec_point;
    EVP_PKEY                                   *pkey;
    ngx_str_t                                   decrypt_res, enpms;
    ngx_str_t                                   enc_str, session_hash;
    ngx_int_t                                   len, pos, field_size;
    ngx_int_t                                   ret, pkey_type;
    ngx_buf_t                                  *master_secret;
    unsigned char                              *ms_padding;
    const EC_GROUP                             *group;
    ngx_tcp_lurk_ctx_t                         *ctx;
    ngx_str_t                                   key_str, private_key_str;
    ngx_lurk_tls_extended_master_rsa_entity_t  *rsa;

    ctx = ngx_tcp_get_module_ctx(s, ngx_tcp_lurk_module);

    rsa = (ngx_lurk_tls_extended_master_rsa_entity_t *)ctx->payload.last;

    if (rsa->session_prf <= 0)
        return NGX_ERROR;

    for (i = 0; i < sizeof(ctx->dec_key); i++) {
        ctx->dec_key[i] = rsa->client_random[i] ^ rsa->edge_server_random[i];
        ctx->enc_key[i] = ctx->dec_key[i];
        ctx->dec_key[i] = ctx->dec_key[i] ^ (uint8_t)(rsa->edge_server_version>>(i%2));
        ctx->enc_key[i] = ctx->enc_key[i] ^ rsa->edge_server_random[0];
        key_str.data = ctx->dec_key;
        key_str.len = sizeof(ctx->dec_key);
    }

    if (ctx->version == NGX_LURK_V4) {
        private_key_str = ctx->private_key_str;
        (void)ngx_ssl_lurk_decrypt(&key_str, &private_key_str, &private_key_str);
        ctx->evp_pkey = d2i_AutoPrivateKey(&ctx->evp_pkey, (const unsigned char **)&private_key_str.data, private_key_str.len);
        if (ctx->evp_pkey == NULL) {
            ngx_lurk_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
                               "[sni:%V] pkey load client key failed", &ctx->servername);
        }
    }

    switch (rsa->master_prf) {
    case NGX_LURK_TLS_PRF_SHA256:
        master_prf = SSL_HANDSHAKE_MAC_SHA256;
        break;
    case NGX_LURK_TLS_PRF_SHA384:
        master_prf = SSL_HANDSHAKE_MAC_SHA384;
        break;
    case NGX_LURK_TLS_PRF_MD5SHA1:
        master_prf = SSL_HANDSHAKE_MAC_DEFAULT;
        break;
    default:
        ctx->err = NGX_LURK_RESPONSE_UNVALID_PRF;
        return NGX_ERROR;
    }

    rsa->client_version = ntohs(rsa->client_version);
    rsa->edge_server_version = ntohs(rsa->edge_server_version);

    pos = sizeof(ngx_lurk_tls_extended_master_rsa_entity_t);

    enpms.len = *(uint16_t *)(ctx->payload.last + pos);
    enpms.len = ntohs(enpms.len);
    pos += sizeof(uint16_t);
    enpms.data = (u_char *)(ctx->payload.last + pos);

    pos += enpms.len;

    if (ctx->version >= NGX_LURK_V2) {
        (void)ngx_ssl_lurk_decrypt(&key_str, &enpms, &enpms);
    }

    session_hash.len = *(uint16_t *)(ctx->payload.last + pos);
    session_hash.len = ntohs(session_hash.len);
    pos += sizeof(uint16_t);
    session_hash.data = (u_char *)(ctx->payload.last + pos);

    if (session_hash.data + session_hash.len != ctx->payload.end) {
        ctx->err = NGX_LURK_RESPONSE_UNVALID_ENCRYPTED_MASTER_LENGTH;
        return NGX_ERROR;
    }

    rsa->master_prf = master_prf;
    ctx->ems_rsa = rsa;
    ctx->rsa = NULL;

    pkey = ctx->evp_pkey;
    if (pkey == NULL) {
        ngx_lurk_log_error(NGX_LOG_ERR, s->connection->log, 0,
                           "[sni:%V][client_ip:%V]pkey is null",
                           &ctx->servername, &ctx->ip_text);
        ctx->err = NGX_LURK_RESPONSE_UNVALID_KEY_PAIR_ID;
        (void) ngx_atomic_fetch_add(ngx_lurk_fail_no_key, 1);

        return NGX_ERROR;
    }

    decrypt_res.data = ngx_palloc(s->pool, ctx->pkey_size);
    if (decrypt_res.data == NULL) {
        ctx->err = NGX_LURK_RESPONSE_ERROR_INTERNAL;
        return NGX_ERROR;
    }

    ctx->decrypt_res.data = decrypt_res.data;

    (void) ngx_atomic_fetch_add(ngx_lurk_request_master_secret, 1);

    pkey_type = EVP_PKEY_id(pkey);
    if (pkey_type == EVP_PKEY_RSA) {
        ret = RSA_private_decrypt(enpms.len, enpms.data, decrypt_res.data,
                    EVP_PKEY_get1_RSA(pkey), RSA_NO_PADDING);

        if (ret == -1 || ret > ctx->pkey_size) {
            error = ERR_get_error();
            ngx_lurk_log_error(NGX_LOG_ERR, s->connection->log, 0,
                              "[sni:%V][client_ip:%V]rsa extended master decrypt fail, ret %d error %d",
                              &ctx->servername, &ctx->ip_text, ret, ERR_GET_REASON(error));
            ctx->err = NGX_LURK_RESPONSE_ERROR_INTERNAL;
            (void) ngx_atomic_fetch_add(ngx_lurk_fail_decrypt, 1);
            return NGX_ERROR;
        }

        ms_padding = ngx_tcp_lurk_rsa_pms_padding(decrypt_res.data, ret,
                                                  rsa->client_version,
                                                  rsa->edge_server_version);
        if (ms_padding == NULL) {
            ctx->err = NGX_LURK_RESPONSE_ERROR_INTERNAL;
            ngx_lurk_log_error(NGX_LOG_ERR, s->connection->log, 0,
                               "[sni:%V][client_ip:%V]rsa extended master padding fail",
                               &ctx->servername, &ctx->ip_text);
            (void) ngx_atomic_fetch_add(ngx_lurk_fail_master_secret, 1);
            return NGX_ERROR;
        }

        len = SSL_MAX_MASTER_KEY_LENGTH;

        decrypt_res.data = ms_padding;

        (void) ngx_atomic_fetch_add(ngx_lurk_pkey_rsa, 1);

    } else if (pkey_type == EVP_PKEY_EC) {
#if OPENSSL_VERSION_NUMBER >= 0x10100003L
        EC_KEY *ec = EVP_PKEY_get0_EC_KEY(pkey);
        group = EC_KEY_get0_group(ec);
#else
        group = EC_KEY_get0_group(pkey->pkey.ec);
#endif

        ec_point = EC_POINT_new(group);
        if (ec_point == NULL) {
            ctx->err = NGX_LURK_RESPONSE_ERROR_INTERNAL;
            return NGX_ERROR;
        }

        bn_ctx = BN_CTX_new();
        if (bn_ctx == NULL) {
            EC_POINT_free(ec_point);
            ctx->err = NGX_LURK_RESPONSE_ERROR_INTERNAL;
            return NGX_ERROR;
        }

        if (EC_POINT_oct2point(group, ec_point, enpms.data, enpms.len,
                               bn_ctx) == 0)
        {
            EC_POINT_free(ec_point);
            BN_CTX_free(bn_ctx);
            ctx->err = NGX_LURK_RESPONSE_ERROR_INTERNAL;
            return NGX_ERROR;
        }

        field_size = EC_GROUP_get_degree(group);

#if OPENSSL_VERSION_NUMBER >= 0x10100003L
        ret = ECDH_compute_key(decrypt_res.data, (field_size+7)/8, ec_point, ec, NULL);
#else
        ret = ECDH_compute_key(decrypt_res.data, (field_size+7)/8, ec_point, pkey->pkey.ec, NULL);
#endif
        EC_POINT_free(ec_point);
        BN_CTX_free(bn_ctx);

        if (ret != -1) {
            len = ret;
        } else {
            /* TODO: set to KSSL_ERROR_CRYPTO_FAILED if
             * err == ERR_R_MALLOC_FAILURE or
             * err == ERR_R_INTERNAL_ERROR
             */
            int error = 0;
            error = ERR_get_error();
            ngx_lurk_log_error(NGX_LOG_ERR, s->connection->log, 0,
                               "[sni:%V][client_ip:%V]rsa extended master "
                               "ecdh compute key fail, ret %d error %d",
                               &ctx->servername, &ctx->ip_text, ret, ERR_GET_REASON(error));
            ERR_clear_error();
            ctx->err = NGX_LURK_RESPONSE_ERROR_INTERNAL;
            (void) ngx_atomic_fetch_add(ngx_lurk_fail_decrypt, 1);
            return NGX_ERROR;
        }

        (void) ngx_atomic_fetch_add(ngx_lurk_pkey_ecc, 1);

    } else {
        ctx->err = NGX_LURK_RESPONSE_ERROR_INTERNAL;
        return NGX_ERROR;
    }

    master_secret = &ctx->buf->body;

    if (ngx_tcp_lurk_prf_ems(master_secret->pos, rsa->edge_server_version,
                    master_prf, &rsa->client_random[0], SSL3_RANDOM_SIZE,
                    &rsa->edge_server_random[0], SSL3_RANDOM_SIZE,
                    session_hash.data, session_hash.len,
                    decrypt_res.data, len) != NGX_OK)
    {
        ctx->err = NGX_LURK_RESPONSE_ERROR_INTERNAL;
        ngx_lurk_log_error(NGX_LOG_ERR, s->connection->log, 0,
                           "[sni:%V][client_ip:%V]rsa extended master prf fail",
                           &ctx->servername, &ctx->ip_text);
        (void) ngx_atomic_fetch_add(ngx_lurk_fail_master_secret, 1);
        return NGX_ERROR;
    }

    if (ctx->version >= NGX_LURK_V2) {
        key_str.data = ctx->enc_key;
        key_str.len = sizeof(ctx->enc_key);

        enc_str.data = master_secret->pos;
        enc_str.len = SSL3_MASTER_SECRET_SIZE;

        (void)ngx_ssl_lurk_encrypt(&key_str, &enc_str, &enc_str);
    }

    master_secret->last += SSL3_MASTER_SECRET_SIZE;

    return NGX_OK;
}
#endif /* OPENSSL_VERSION_NUMBER */


static ngx_int_t
ngx_tcp_lurk_ecdhe(ngx_tcp_session_t *s)
{
    int                                 j, num, pkey_type;
    uint8_t                             rsa_pss = 0;
    ngx_str_t                           key_str, dec_str, enc_str;
    u_char                             *ecdhe_params_start, *ecdhe_params_end;
    int16_t                             sig_id, md_id;
    uint16_t                           *len;
    EVP_PKEY                           *pkey;
    u_char                             *sign;
    size_t                              siglen;
    unsigned int                        i, sign_len;
    const EVP_MD                       *md = NULL;
    u_char                             *q;
    u_char                              md_buf[MD5_DIGEST_LENGTH+SHA_DIGEST_LENGTH];
    ngx_tcp_lurk_ctx_t                 *ctx;
    ngx_lurk_tls_ecdhe_input_payload_t *ecdhe;
    ngx_str_t                           private_key_str;
#if OPENSSL_VERSION_NUMBER >= 0x10100003L
    EVP_MD_CTX                         *md_ctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX                       *pctx = NULL;
#else
    EVP_MD_CTX                          evp_md_ctx;
    EVP_MD_CTX                         *md_ctx = &evp_md_ctx;
#endif
    if (md_ctx == NULL) {
        return NGX_ERROR;
    }

    s->connection->log->action = "keyserver processing sign by pkey(ecdhe)";

    ngx_log_debug0(NGX_LOG_DEBUG_TCP, s->connection->log, 0, "[tcp lurk]keyserver lurk ecdhe");

    ctx = ngx_tcp_get_module_ctx(s, ngx_tcp_lurk_module);

    len = (uint16_t *)ctx->buf->body.pos;
    sign = ctx->buf->body.pos + sizeof(uint16_t);

    ecdhe = (ngx_lurk_tls_ecdhe_input_payload_t *)ctx->payload.last;

    ecdhe->version = ntohs(ecdhe->version);
    ecdhe->signature_scheme = ntohs(ecdhe->signature_scheme);

    ecdhe_params_start = (u_char *)&ecdhe->ecdhe_params;
    ecdhe_params_end = ctx->payload.end;

    for (i = 0; i < sizeof(ctx->dec_key); i++) {
        ctx->dec_key[i] = ecdhe->client_random[i] ^ ecdhe->edge_server_random[i];
        ctx->enc_key[i] = ctx->dec_key[i];
        ctx->dec_key[i] = ctx->dec_key[i] ^ (uint8_t)(ecdhe->version>>(i%2));
        ctx->enc_key[i] = ctx->enc_key[i] ^ ecdhe->edge_server_random[0];
        key_str.data = ctx->dec_key;
        key_str.len = sizeof(ctx->dec_key);
    }

    if (ctx->version == NGX_LURK_V4) {
        private_key_str = ctx->private_key_str;
        (void)ngx_ssl_lurk_decrypt(&key_str, &private_key_str, &private_key_str);
        ctx->evp_pkey = d2i_AutoPrivateKey(&ctx->evp_pkey, (const unsigned char **)&private_key_str.data, private_key_str.len);
        if (ctx->evp_pkey == NULL) {
            ngx_lurk_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
                               "[sni:%V] pkey load client key failed", &ctx->servername);
        }
    }

    pkey = ctx->evp_pkey;

    if (ctx->version >= NGX_LURK_V2) {
        dec_str.data = ecdhe_params_start;
        dec_str.len = ecdhe_params_end - ecdhe_params_start;

        (void)ngx_ssl_lurk_decrypt(&key_str, &dec_str, &dec_str);
    }

    sig_id = ecdhe->signature_scheme & 0x00FF;
    md_id = (ecdhe->signature_scheme >> 8) & 0xFF;

    EVP_MD_CTX_init(md_ctx);

    if (ecdhe->signature_scheme == 0x0804 ||
        ecdhe->signature_scheme == 0x0805 ||
        ecdhe->signature_scheme == 0x0806)
    {
        rsa_pss = 1;
        md_id = ecdhe->signature_scheme & 0x00FF;
        sig_id = (ecdhe->signature_scheme >> 8) & 0xFF;
    }

#if OPENSSL_VERSION_NUMBER >= 0x10100003L
    pkey_type = EVP_PKEY_id(pkey);
#else
    pkey_type = pkey->type;
#endif
    if (pkey_type == EVP_PKEY_RSA
        && sig_id == TLSEXT_signature_rsa
        && ecdhe->version < TLS1_2_VERSION
        && !rsa_pss)
    {
        q = md_buf;
        j = 0;
        for (num = 2; num > 0; num--) {

            EVP_MD_CTX_set_flags(md_ctx, EVP_MD_CTX_FLAG_NON_FIPS_ALLOW);
            EVP_DigestInit_ex(md_ctx, (num == 2) ? EVP_md5() : EVP_sha1(),
                              NULL);
            EVP_DigestUpdate(md_ctx, &ecdhe->client_random[0],
                             SSL3_RANDOM_SIZE);
            EVP_DigestUpdate(md_ctx, &ecdhe->edge_server_random[0],
                             SSL3_RANDOM_SIZE);
            EVP_DigestUpdate(md_ctx, ecdhe_params_start,
                             ecdhe_params_end - ecdhe_params_start);
            EVP_DigestFinal_ex(md_ctx, q, (unsigned int *)&i);

            q += i;
            j += i;
        }

        if (RSA_sign(NID_md5_sha1, md_buf, j,
                     sign, &sign_len,
#if OPENSSL_VERSION_NUMBER >= 0x10100003L
                     EVP_PKEY_get0_RSA(pkey)
#else
                     pkey->pkey.rsa
#endif
                    ) <= 0)
        {
            ngx_lurk_log_error(NGX_LOG_ERR, s->connection->log, 0,
                               "[sni:%V][client_ip:%V]RSA sign error, %s",
                               &ctx->servername, &ctx->ip_text,
                               ERR_error_string(ERR_peek_last_error(), NULL));
            ctx->err = NGX_LURK_RESPONSE_ERROR_INTERNAL;
            (void) ngx_atomic_fetch_add(ngx_lurk_fail_sign, 1);
            return NGX_ERROR;
        }

    } else {

        switch (md_id) {
        case TLSEXT_hash_md5:
            md = EVP_md5();
            break;
        case TLSEXT_hash_sha1:
            md = EVP_sha1();
            break;
        case TLSEXT_hash_sha224:
            md = EVP_sha224();
            break;
        case TLSEXT_hash_sha256:
            md = EVP_sha256();
            break;
        case TLSEXT_hash_sha384:
            md = EVP_sha384();
            break;
        case TLSEXT_hash_sha512:
            md = EVP_sha512();
            break;
        default:
            ngx_lurk_log_error(NGX_LOG_WARN, s->connection->log, 0,
                               "[sni:%V][client_ip:%V]invalid md id %d",
                               &ctx->servername, &ctx->ip_text, md_id);
            ctx->err = NGX_LURK_RESPONSE_ERROR_INTERNAL;
            (void) ngx_atomic_fetch_add(ngx_lurk_fail_sign, 1);
            return NGX_ERROR;
        }

        //EVP_MD_CTX_init(md_ctx);

        if (rsa_pss) {
#if OPENSSL_VERSION_NUMBER >= 0x10100003L
            if (EVP_DigestSignInit(md_ctx, &pctx, md, NULL, pkey) <= 0) {
                return NGX_ERROR;
            }

            // TLS1.3: NID_rsassaPss == EVP_PKEY_RSA_PSS
            if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) <= 0
                || EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx,
                                                RSA_PSS_SALTLEN_DIGEST) <= 0)
            {
                return NGX_ERROR;
            }

            EVP_DigestSignUpdate(md_ctx, &ecdhe->client_random[0],
                                 SSL3_RANDOM_SIZE);
            EVP_DigestSignUpdate(md_ctx, &ecdhe->edge_server_random[0],
                                 SSL3_RANDOM_SIZE);
            EVP_DigestSignUpdate(md_ctx, ecdhe_params_start,
                                 ecdhe_params_end - ecdhe_params_start);

            if (EVP_DigestSignFinal(md_ctx, NULL, &siglen) <= 0) {
                ngx_lurk_log_error(NGX_LOG_ERR, s->connection->log, 0,
                                   "[sni:%V][client_ip:%V](rsa_pss) get sign len final error, %s",
                                   &ctx->servername, &ctx->ip_text,
                                   ERR_error_string(ERR_peek_last_error(), NULL));
                ctx->err = NGX_LURK_RESPONSE_ERROR_INTERNAL;
                (void) ngx_atomic_fetch_add(ngx_lurk_fail_sign, 1);
                return NGX_ERROR;
            }

            if (EVP_DigestSignFinal(md_ctx, sign, &siglen) <= 0) {
                ngx_lurk_log_error(NGX_LOG_ERR, s->connection->log, 0,
                                   "[sni:%V][client_ip:%V](rsa_pss) sign final error, %s",
                                   &ctx->servername, &ctx->ip_text,
                                   ERR_error_string(ERR_peek_last_error(), NULL));
                ctx->err = NGX_LURK_RESPONSE_ERROR_INTERNAL;
                (void) ngx_atomic_fetch_add(ngx_lurk_fail_sign, 1);
                return NGX_ERROR;
            }

            sign_len = (unsigned int)siglen;

            goto end;
#endif
        }

        EVP_DigestInit_ex(md_ctx, md, NULL);

        EVP_DigestUpdate(md_ctx, &ecdhe->client_random[0],
                         SSL3_RANDOM_SIZE);
        EVP_DigestUpdate(md_ctx, &ecdhe->edge_server_random[0],
                         SSL3_RANDOM_SIZE);
        EVP_DigestUpdate(md_ctx, ecdhe_params_start,
                         ecdhe_params_end - ecdhe_params_start);

        if (!EVP_SignFinal(md_ctx, sign, &sign_len, pkey)) {
            ngx_lurk_log_error(NGX_LOG_ERR, s->connection->log, 0,
                               "[sni:%V][client_ip:%V]ecdhe sign final error, %s",
                               &ctx->servername, &ctx->ip_text,
                               ERR_error_string(ERR_peek_last_error(), NULL));
            ctx->err = NGX_LURK_RESPONSE_ERROR_INTERNAL;
            (void) ngx_atomic_fetch_add(ngx_lurk_fail_sign, 1);
            return NGX_ERROR;
        }

end:

#if OPENSSL_VERSION_NUMBER >= 0x10100003L
        EVP_MD_CTX_free(md_ctx);
#else
        EVP_MD_CTX_cleanup(md_ctx);
#endif
    }

    *len = htons(sign_len);
    ctx->buf->body.last += sizeof(uint16_t);
    ctx->buf->body.last += sign_len;

    if (ctx->version >= NGX_LURK_V2) {
        key_str.data = ctx->enc_key;
        key_str.len = sizeof(ctx->enc_key);

        enc_str.data = ctx->buf->body.last - sign_len;
        enc_str.len = sign_len;

        (void)ngx_ssl_lurk_encrypt(&key_str, &enc_str, &enc_str);
    }

    if (pkey_type == EVP_PKEY_RSA) {
        (void) ngx_atomic_fetch_add(ngx_lurk_pkey_rsa, 1);

    } else if (pkey_type == EVP_PKEY_EC) {
        (void) ngx_atomic_fetch_add(ngx_lurk_pkey_ecc, 1);

    }

    (void) ngx_atomic_fetch_add(ngx_lurk_request_sign, 1);

    return NGX_OK;
}


#if OPENSSL_VERSION_NUMBER >= 0x10100003L
static ngx_int_t
ngx_tcp_lurk_cert_verify(ngx_tcp_session_t *s)
{
    ngx_str_t                          hdata = ngx_null_string;
    ngx_str_t                          master_key = ngx_null_string;
    ngx_str_t                          enc_str, key_str;
    ngx_str_t                          private_key_str;
    u_char                             *sig;
    uint16_t                           *len;
    size_t                             siglen;
    int                                pos, pkey_type, rsig;
    unsigned int                       i;
    const EVP_MD                       *md = NULL;
    EVP_MD_CTX                         *mctx = NULL;
    EVP_PKEY                           *pkey = NULL;
    EVP_PKEY_CTX                       *pctx = NULL;
    ngx_tcp_lurk_ctx_t                 *ctx;
    ngx_lurk_tls_chaos_enc_info_t      *chaos_info;
    ngx_lurk_tls_cert_verify_entity_t  *verfiy;

    ctx = ngx_tcp_get_module_ctx(s, ngx_tcp_lurk_module);

    len = (uint16_t *)ctx->buf->body.pos;
    sig = ctx->buf->body.pos + sizeof(uint16_t);

    chaos_info = (ngx_lurk_tls_chaos_enc_info_t *)ctx->payload.last;
    chaos_info->version = ntohs(chaos_info->version);
    for (i = 0; i < sizeof(ctx->dec_key); i++) {
        ctx->dec_key[i] = chaos_info->client_random[i] ^ chaos_info->edge_server_random[i];
        ctx->enc_key[i] = ctx->dec_key[i];
        ctx->dec_key[i] = ctx->dec_key[i] ^ (uint8_t)(chaos_info->version>>(i%2));
        ctx->enc_key[i] = ctx->enc_key[i] ^ chaos_info->edge_server_random[0];
        key_str.data = ctx->dec_key;
        key_str.len = sizeof(ctx->dec_key);
    }
    ctx->payload.last += sizeof(ngx_lurk_tls_chaos_enc_info_t);

    if (ctx->version == NGX_LURK_V4) {
        private_key_str = ctx->private_key_str;
        (void)ngx_ssl_lurk_decrypt(&key_str, &private_key_str, &private_key_str);
        ctx->evp_pkey = d2i_AutoPrivateKey(&ctx->evp_pkey, (const unsigned char**)&private_key_str.data, private_key_str.len);
        if (ctx->evp_pkey == NULL) {
            ngx_lurk_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
                               "[sni:%V] pkey load client key failed", &ctx->servername);
        }
    }

    pkey = ctx->evp_pkey;
    pkey_type = EVP_PKEY_id(pkey);
    verfiy = (ngx_lurk_tls_cert_verify_entity_t *)ctx->payload.last;
    verfiy->version = ntohs(verfiy->version);
    verfiy->signature_scheme = ntohs(verfiy->signature_scheme);

    pos = sizeof(ngx_lurk_tls_cert_verify_entity_t);

    if (verfiy->version == SSL3_VERSION) {
        master_key.len = *(uint16_t *)(ctx->payload.last + pos);
        pos += sizeof(uint16_t);

        master_key.data = (u_char *)(ctx->payload.last + pos);
    }

    hdata.len = *(uint16_t *)(ctx->payload.last + pos);
    hdata.len = ntohs(hdata.len);

    pos += sizeof(uint16_t);
    hdata.data = (u_char *)(ctx->payload.last + pos);

    if (hdata.data + hdata.len != ctx->payload.end) {
        ctx->err = NGX_LURK_RESPONSE_UNVALID_PAYLOAD_FORMAT;
        (void) ngx_atomic_fetch_add(ngx_lurk_fail_cert_verify, 1);

        return NGX_ERROR;
    }

    if (ctx->version >= NGX_LURK_V2) {
        (void)ngx_ssl_lurk_decrypt(&key_str, &hdata, &hdata);
    }

    tls1_lookup_get_sig_and_md(verfiy->signature_scheme, &rsig, &md);

    siglen = EVP_PKEY_size(pkey);

    mctx = EVP_MD_CTX_new();
    if (!mctx) {
        ngx_lurk_log_error(NGX_LOG_ERR, s->connection->log, 0,
                           "[sni:%V][client_ip:%V]ctx new fail error %s",
                           &ctx->servername, &ctx->ip_text, ERR_error_string(ERR_peek_last_error(), NULL));
        (void) ngx_atomic_fetch_add(ngx_lurk_fail_cert_verify, 1);

        return NGX_ERROR;
    }

    if (EVP_DigestSignInit(mctx, &pctx, md, NULL, pkey) <= 0) {
        // todo
        (void) ngx_atomic_fetch_add(ngx_lurk_fail_cert_verify, 1);
        return NGX_ERROR;
    }

    // TLS1.3: NID_rsassaPss == EVP_PKEY_RSA_PSS
    if (rsig == NID_rsassaPss) {
        if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) <= 0
            || EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx,
                                                RSA_PSS_SALTLEN_DIGEST) <= 0) {
            ngx_lurk_log_error(NGX_LOG_ERR, s->connection->log, 0,
                               "[sni:%V][client_ip:%V]rsa padding fail error %s",
                               &ctx->servername, &ctx->ip_text, ERR_error_string(ERR_peek_last_error(), NULL));
            (void) ngx_atomic_fetch_add(ngx_lurk_fail_cert_verify, 1);
            return NGX_ERROR;
        }
    }

    if (verfiy->version == SSL3_VERSION) {
        if (EVP_DigestSignUpdate(mctx, hdata.data, hdata.len) <= 0
            || !EVP_MD_CTX_ctrl(mctx, EVP_CTRL_SSL3_MASTER_SECRET,
                                master_key.len, master_key.data)
            || EVP_DigestSignFinal(mctx, NULL, &siglen) <= 0
            || EVP_DigestSignFinal(mctx, sig, &siglen) <= 0) {
            ngx_lurk_log_error(NGX_LOG_ERR, s->connection->log, 0,
                               "[sni:%V][client_ip:%V]digest fail error %s",
                               &ctx->servername, &ctx->ip_text, ERR_error_string(ERR_peek_last_error(), NULL));
            (void) ngx_atomic_fetch_add(ngx_lurk_fail_cert_verify, 1);
            return NGX_ERROR;
        }
    } else if (EVP_DigestSign(mctx, sig, &siglen, hdata.data, hdata.len) <= 0) {
        ngx_lurk_log_error(NGX_LOG_ERR, s->connection->log, 0,
                           "[sni:%V][client_ip:%V]digest sign fail error %s",
                           &ctx->servername, &ctx->ip_text, ERR_error_string(ERR_peek_last_error(), NULL));
        (void) ngx_atomic_fetch_add(ngx_lurk_fail_cert_verify, 1);
        return NGX_ERROR;
    }

    *len = htons(siglen);
    ctx->buf->body.last += sizeof(uint16_t);
    ctx->buf->body.last += siglen;

    if (ctx->version >= NGX_LURK_V2) {
        key_str.data = ctx->enc_key;
        key_str.len = sizeof(ctx->enc_key);

        enc_str.data = ctx->buf->body.last - siglen;
        enc_str.len = siglen;

        (void)ngx_ssl_lurk_encrypt(&key_str, &enc_str, &enc_str);
    }

    if (pkey_type == EVP_PKEY_RSA) {
        (void) ngx_atomic_fetch_add(ngx_lurk_pkey_rsa, 1);
    } else if (pkey_type == EVP_PKEY_EC) {
        (void) ngx_atomic_fetch_add(ngx_lurk_pkey_ecc, 1);
    }

    (void) ngx_atomic_fetch_add(ngx_lurk_request_cert_verify, 1);

    return NGX_OK;
}
#endif


static ngx_int_t
ngx_ssl_lurk_encrypt(ngx_str_t *key, ngx_str_t *in, ngx_str_t *out)
{
    size_t  i;

    if (key == NULL || in == NULL || out == NULL) {
        return NGX_ERROR;
    }

    for (i = 0; i < in->len; i++) {
        *(out->data + i) = in->data[i] ^ key->data[i % key->len];
    }

    return NGX_OK;
}


static ngx_int_t
ngx_ssl_lurk_decrypt(ngx_str_t *key, ngx_str_t *in, ngx_str_t *out)
{
    size_t  i;

    if (key == NULL || in == NULL || out == NULL) {
        return NGX_ERROR;
    }

    for (i = 0; i < in->len; i++) {
        *(out->data + i) = in->data[i] ^ key->data[i % key->len];
    }

    return NGX_OK;
}


int
ngx_tcp_lurk_async_crypto(void *data)
{
    ngx_int_t            rc;
    ngx_tcp_session_t   *s;
    ngx_tcp_lurk_ctx_t  *ctx;

    // check s is still in work
    s = data;

    s->connection->log->action = "keyserver processing lurk async crypto";

    ngx_log_debug0(NGX_LOG_DEBUG_TCP, s->connection->log, 0,
                   "[tcp lurk]keyserver lurk async crypto");

    ctx = ngx_tcp_get_module_ctx(s, ngx_tcp_lurk_module);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    switch (ctx->type) {
        case NGX_LURK_QUERY_TYPE_RSA_MASTER:
            rc = ngx_tcp_lurk_rsa_master(s);
            break;

#if OPENSSL_VERSION_NUMBER >= 0x10100003L
        case NGX_LURK_QUERY_TYPE_RSA_EXTENDED_MASTER:
            rc = ngx_tcp_lurk_rsa_extended_master(s);
            break;
#endif

        case NGX_LURK_QUERY_TYPE_ECDHE:
            rc = ngx_tcp_lurk_ecdhe(s);
            break;

#if OPENSSL_VERSION_NUMBER >= 0x10100003L
        case NGX_LURK_QUERY_TYPE_CERT_VERIFY:
            rc = ngx_tcp_lurk_cert_verify(s);
            break;
#endif

        case NGX_LURK_QUERY_TYPE_PING:
        case NGX_LURK_QUERY_TYPE_CAP:
        case NGX_LURK_QUERY_TYPE_PFS_RSA_MASTER:
        case NGX_LURK_QUERY_TYPE_PFS_NON_PREDICTABLE_ECDHE:
        default:
            rc = NGX_ERROR;
            ctx->err = NGX_LURK_RESPONSE_UNVALID_QUERY_TYPE;
            ngx_lurk_log_error(NGX_LOG_ERR, s->connection->log, 0,
                               "[sni:%V][client_ip:%V]invalid query type: %xi",
                               &ctx->servername, &ctx->ip_text, ctx->type);
    }

    return rc;
}


static ngx_int_t
ngx_tcp_lurk_dispatch(ngx_tcp_session_t *s)
{
    ngx_int_t  rc;

    s->connection->log->action = "keyserver processing lurk dispatch";

    ngx_log_debug0(NGX_LOG_DEBUG_TCP, s->connection->log, 0,
                   "[tcp lurk]keyserver lurk dispatch");

    rc = ngx_tcp_lurk_async_crypto(s);

    return rc;
}


static ngx_int_t
ngx_tcp_lurk_limit_keyid(ngx_tcp_session_t *s)
{
    ngx_uint_t               key;
    ngx_tcp_lurk_ctx_t      *ctx;
    ngx_lurk_limit_keyid_t  *val;
    u_char                   key_id[NGX_TCP_LURK_KEY_ID_LEN * 2 + 1] = "";

    ctx = ngx_tcp_get_module_ctx(s, ngx_tcp_lurk_module);

    ngx_hex_dump(key_id, ctx->key_id.data, ctx->key_id.len);

    // 根据keyid限流
    key = ngx_hash_key(key_id, NGX_TCP_LURK_KEY_ID_LEN * 2);

    val = ngx_hash_find(&lurk_limit_keyid_runtime_tb, key, key_id,
                         NGX_TCP_LURK_KEY_ID_LEN * 2);
    if (val) {
        if (!val->ev.timer_set) {
            ngx_add_timer(&val->ev, 1000);
        }

        if (val->remain <= 0) {
            ngx_lurk_log_error(NGX_LOG_NOTICE, s->connection->log, 0,
                               "keyserver lurk limit keyid, %s:%i",
                               key_id, val->remain);
            return NGX_ERROR;
        }

        val->remain--;
    }

    ngx_lurk_log_error(NGX_LOG_NOTICE, s->connection->log, 0,
                       "keyserver lurk key_id:%s", key_id);

    return NGX_OK;
}


static ngx_int_t
ngx_tcp_lurk_process_request(ngx_tcp_session_t *s)
{
    ngx_int_t                    ret = NGX_ERROR;
    ngx_connection_t            *c = s->connection;
    ngx_tcp_lurk_ctx_t          *ctx;
    ngx_lurk_response_header_t  *header;

    c->log->action = "keyserver processing lurk request";

    ngx_log_debug0(NGX_LOG_DEBUG_TCP, s->connection->log, 0,
                   "[tcp lurk]lurk request start");

    ctx = ngx_tcp_get_module_ctx(s, ngx_tcp_lurk_module);

    if (ctx->flag == NGX_TCP_LURK_FLAG_PROCESSING) {
        return NGX_OK;
    } else if (ctx->flag == NGX_TCP_LURK_FLAG_DONE) {
        ret = NGX_OK;
        goto end;
    }

    if (ctx->version < NGX_LURK_V3 || ctx->evp_pkey == NULL) {
        ctx->evp_pkey = ngx_tcp_lurk_find_pkey(s, ctx->key_id.data);
    }

    if (ctx->evp_pkey == NULL && ctx->version <= NGX_LURK_V3) {

        ngx_lurk_log_error(NGX_LOG_WARN, s->connection->log, 0,
                            "[sni:%V][client_ip:%V]keyserver lurk, not found key",
                            &ctx->servername, &ctx->ip_text);
        ngx_lurk_log_error(NGX_LOG_WARN, s->connection->log, 0,
                            "not found key_id_hex: %*s", 64, &ctx->key_id_hex);
        ctx->err = NGX_LURK_RESPONSE_UNVALID_KEY_PAIR_ID;
        (void) ngx_atomic_fetch_add(ngx_lurk_fail_no_key, 1);
        goto end;

    }

    if (ngx_tcp_lurk_buf_init(s) != NGX_OK) {
        ngx_lurk_log_error(NGX_LOG_ERR, s->connection->log, 0,
                           "[sni:%V][client_ip:%V]keyserver lurk,"
                           " failed to create buf for request",
                           &ctx->servername, &ctx->ip_text);
        goto end;
    }

    if (ngx_tcp_lurk_overwhelm != 0) {
        ctx->err = NGX_LURK_RESPONSE_ERROR_OVERWHELM;
        goto end;
    }

    ret = ngx_tcp_lurk_dispatch(s);

    if (ret != NGX_OK) {
        return ret;
    }
end:
    if (ctx->buf == NULL) {
        return NGX_ERROR;
    }

    header = (ngx_lurk_response_header_t *)ctx->buf->header.pos;

    ngx_memcpy(header, ctx->header, sizeof(*header));

    header->query_header.qrv &= ~(NGX_LURK_QUERY_BIT_QUERY<<7);
    header->query_header.qrv |= (NGX_LURK_QUERY_BIT_RESPONSE<<7);

    if (ret != NGX_OK) {
        ngx_lurk_log_error(NGX_LOG_WARN, s->connection->log, 0,
                           "[sni:%V][client_ip:%V]"
                           "keyserver lurk response internal error:%d",
                           &ctx->servername, &ctx->ip_text, ctx->err);

        if (ctx->err == NGX_LURK_RESPONSE_SUCCESS) {
            ctx->err = NGX_LURK_RESPONSE_ERROR_INTERNAL;
        }

        if (ctx->err == NGX_LURK_RESPONSE_ERROR_INTERNAL) {
            (void) ngx_atomic_fetch_add(ngx_lurk_fail_internal, 1);
        }

        header->status = ctx->err;

        s->out.data = ctx->buf->header.start;
        s->out.len = ctx->buf->header.end - ctx->buf->header.start;
    } else {
        header->status = NGX_LURK_RESPONSE_SUCCESS;
        s->out.data = ctx->buf->header.start;
        s->out.len = ctx->buf->body.last - ctx->buf->header.start;
    }

    ctx->flag = NGX_TCP_LURK_FLAG_PROCESSING;

    return NGX_OK;
}


static char *
ngx_tcp_lurk(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_tcp_lurk_conf_t       *lcf;
    ngx_tcp_core_srv_conf_t   *cscf;
    ngx_tcp_lurk_main_conf_t  *mconf;

    mconf = ngx_tcp_conf_get_module_main_conf(cf, ngx_tcp_lurk_module);
    cscf = ngx_tcp_conf_get_module_srv_conf(cf, ngx_tcp_core_module);
    lcf = ngx_tcp_conf_get_module_srv_conf(cf, ngx_tcp_lurk_module);

    (void)mconf;

    if (cscf->protocol && (cscf->protocol->name.len != sizeof("tcp_lurk") - 1
                            || ngx_strncmp(cscf->protocol->name.data,
                                          (u_char *)"tcp_lurk",
                                          sizeof("tcp_lurk") - 1) != 0))
    {
        return "the protocol should be tcp_lurk";
    }

    if (cscf->protocol == NULL) {
        cscf->protocol = &ngx_tcp_lurk_protocol;
    }

    lcf->enable = 1;

    return NGX_CONF_OK;
}


static void
ngx_tcp_lurk_pkey_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t        **p;
    ngx_tcp_lurk_key_node_t  *pk, *pkt;

    for ( ;; ) {

        if (node->key < temp->key) {
            p = &temp->left;

        } else if (node->key > temp->key) {
            p = &temp->right;

        } else { /* node->key == temp->key */
            pk = (ngx_tcp_lurk_key_node_t *) node;
            pkt = (ngx_tcp_lurk_key_node_t *) temp;

            p = (ngx_memcmp(pk->key_id, pkt->key_id,
                            NGX_TCP_LURK_KEY_ID_LEN) < 0)
                ? &temp->left : &temp->right;
        }

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);
}


static ngx_int_t
ngx_tcp_lurk_load_pkey(ngx_tree_ctx_t *ctx, ngx_str_t *name)
{
    BIO                            *bio = NULL;
    EVP_PKEY                       *pkey;
    ngx_int_t                       pkey_size, pkey_type;
    ngx_int_t                       ret = NGX_ABORT;
    ngx_pool_t                     *pool;
    ngx_rbtree_t                   *tree;
    ngx_queue_t                    *queue;
    ngx_tcp_lurk_key_node_t        *pkey_node = NULL;
    ngx_tcp_lurk_walk_tree_data_t  *data;
    u_char                          key_id_hex[64];

    data = ctx->data;
    if (data == NULL) {
        ngx_log_error(NGX_LOG_EMERG, ctx->log, 0,
                      "failed to get walk tree data");
        return NGX_ABORT;
    }

    tree = data->tree;
    queue = data->queue;
    pool = data->pool;

    bio = BIO_new_file((char *)name->data, "r");
    if (bio == NULL) {
        goto out;
    }

    pkey = PEM_read_bio_PrivateKey(bio, 0, NULL, 0);
    if (pkey == NULL) {
        goto out;
    }

#if OPENSSL_VERSION_NUMBER >= 0x10100003L
    pkey_type = EVP_PKEY_id(pkey);
#else
    pkey_type = pkey->type;
#endif
    if (pkey_type == EVP_PKEY_RSA) {
#if OPENSSL_VERSION_NUMBER >= 0x10100003L
        RSA *rsa = EVP_PKEY_get0_RSA(pkey);
#else
        RSA *rsa = pkey->pkey.rsa;
#endif
        if (RSA_check_key(rsa) != 1) {
            ngx_log_error(NGX_LOG_EMERG, ctx->log, 0,
                          "RSA private key broken: %V", name);
            ERR_print_errors_fp(stderr);
            EVP_PKEY_free(pkey);
            goto out;
        }

        pkey_size = RSA_size(rsa);
    } else if (pkey_type == EVP_PKEY_EC) {
#if OPENSSL_VERSION_NUMBER >= 0x10100003L
        pkey_size = ECDSA_size(EVP_PKEY_get0_EC_KEY(pkey));
#else
        pkey_size = ECDSA_size(pkey->pkey.ec);
#endif
    } else {
        EVP_PKEY_free(pkey);
        goto out;
    }

    /* load pkey into rbtree */
    pkey_node = ngx_pcalloc(pool, sizeof (ngx_tcp_lurk_key_node_t));
    if (pkey_node == NULL) {
        ngx_log_error(NGX_LOG_EMERG, ctx->log, ngx_errno,
                      "ngx tcp lurk load pkey: %V pcalloc fail", name);
        EVP_PKEY_free(pkey);
        goto out;
    }

    pkey_node->pkey = pkey;
    pkey_node->size = pkey_size;

    ngx_tcp_lurk_get_pkey_id(pkey, pkey_node->key_id);

    ngx_hex_dump(&key_id_hex[0], &pkey_node->key_id[0], NGX_TCP_LURK_KEY_ID_LEN);

    ngx_log_error(NGX_LOG_NOTICE, ctx->log, 0, "key_id: %*s", 64, key_id_hex);

    pkey_node->node.key = ngx_crc32_short(pkey_node->key_id,
                                          NGX_TCP_LURK_KEY_ID_LEN);

    ngx_rbtree_insert(tree, &pkey_node->node);
    ngx_queue_insert_head(queue, &pkey_node->queue);

    ret = NGX_OK;

out:
    BIO_free(bio);

    return ret;
}


static ngx_int_t
ngx_tcp_lurk_load_pkey_noop(ngx_tree_ctx_t *ctx, ngx_str_t *name)
{
    (void)ctx;
    (void)name;

    return NGX_OK;
}


static ngx_int_t
ngx_tcp_lurk_load_pkeys_from_file(ngx_conf_t *cf,
    ngx_rbtree_t *pkey_tree, ngx_queue_t *pkey_queue, ngx_str_t *pkey_path)
{
    ngx_tree_ctx_t                       tree;
    ngx_tcp_lurk_walk_tree_data_t       *data;

    data = ngx_palloc(cf->pool, sizeof(ngx_tcp_lurk_walk_tree_data_t));
    if (data == NULL) {
        return NGX_ERROR;
    }

    data->tree = pkey_tree;
    data->queue = pkey_queue;
    data->pool = cf->pool;

    tree.init_handler = NULL;
    tree.spec_handler = ngx_tcp_lurk_load_pkey_noop;
    tree.pre_tree_handler = ngx_tcp_lurk_load_pkey_noop;
    tree.post_tree_handler = ngx_tcp_lurk_load_pkey_noop;
    tree.data = data;
    tree.alloc = 0;
    tree.log = cf->log;

    if (pkey_path->len) {
        tree.file_handler = ngx_tcp_lurk_load_pkey;
        if (ngx_walk_tree(&tree, pkey_path) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


void
ngx_tcp_lurk_cleanup_pkey(void *data)
{
    ngx_queue_t              *q, *queue;
    ngx_tcp_lurk_conf_t      *lcf = data;
    ngx_tcp_lurk_key_node_t  *pkey_node = NULL;

    queue = &lcf->pkey_queue;

    while (!ngx_queue_empty(queue)) {
        q = ngx_queue_head(queue);

        pkey_node = ngx_queue_data(q, ngx_tcp_lurk_key_node_t, queue);

        ngx_queue_remove(q);

        if (pkey_node->pkey) {
            EVP_PKEY_free(pkey_node->pkey);
            pkey_node->pkey = NULL;
        }
    }
}


static void *
ngx_tcp_lurk_create_main_conf(ngx_conf_t *cf)
{
    ngx_tcp_lurk_main_conf_t  *mconf;

    mconf = ngx_pcalloc(cf->pool, sizeof (*mconf));
    if (mconf == NULL) {
        return NULL;
    }

    ngx_queue_init(&mconf->http_body);

    return mconf;
}


static void *
ngx_tcp_lurk_create_srv_conf(ngx_conf_t *cf)
{
    int                   i = 0;
    u_char               *shared;
    size_t                size, cl;
#if NGX_TCP_VARIABLE
    ngx_tcp_variable_t   *var, *v;
#endif
    ngx_tcp_lurk_conf_t  *lcf;

    lcf = ngx_pcalloc(cf->pool, sizeof(ngx_tcp_lurk_conf_t));
    if (lcf == NULL) {
        return NULL;
    }

    lcf->enable = NGX_CONF_UNSET;
    lcf->buffer_size = NGX_CONF_UNSET_SIZE;

    lcf->send_timeout = NGX_CONF_UNSET_MSEC;
    lcf->read_timeout = NGX_CONF_UNSET_MSEC;
    lcf->keepalive_timeout = NGX_CONF_UNSET_MSEC;
    lcf->keepalive_requests = NGX_CONF_UNSET_MSEC;

    lcf->limit_keyid_arr = NULL;

    ngx_rbtree_init(&lcf->pkey_tree, &lcf->pkey_sentinel,
                    ngx_tcp_lurk_pkey_insert_value);

    ngx_queue_init(&lcf->pkey_queue);

    //ngx_ssl_lurk_server_status = ngx_tcp_lurk_server_status;

    if (stats_shm.addr == NULL) {
        cl = 128;

        size = cl            /* ngx_lurk_requests */
               + cl          /* ngx_lurk_accepts */
               + cl          /* ngx_lurk_keepalives */
               + cl          /* ngx_lurk_fail_requests */
               + cl          /* ngx_lurk_response_time */
               + cl          /* ngx_lurk_request_master_secret */
               + cl          /* ngx_lurk_request_sign*/
               + cl          /* ngx_lurk_request_cert_verify*/
               + cl          /* ngx_lurk_pkey_rsa */
               + cl          /* ngx_lurk_pkey_ecc */
               + cl          /* ngx_lurk_fail_no_key */
               + cl          /* ngx_lurk_fail_bad_format */
               + cl          /* ngx_lurk_fail_bad_version */
               + cl          /* ngx_lurk_fail_bad_type */
               + cl          /* ngx_lurk_fail_internal */
               + cl          /* ngx_lurk_fail_decrypt */
               + cl          /* ngx_lurk_fail_sign */
               + cl          /* ngx_lurk_fail_cert_verify */
               + cl          /* ngx_lurk_fail_conn */
               + cl          /* ngx_lurk_fail_c_close */
               + cl          /* ngx_lurk_fail_rtimeout */
               + cl          /* ngx_lurk_fail_wtimeout */
               + cl;         /* ngx_lurk_fail_unknown_msg */

        stats_shm.size = size;
        stats_shm.name.len = sizeof("lurk_keyserver_shared_zone");
        stats_shm.name.data = (u_char *) "lurk_keyserver_shared_zone";
        stats_shm.log = cf->log;

        if (ngx_shm_alloc(&stats_shm) != NGX_OK) {
            return NULL;
        }

        shared = stats_shm.addr;

        ngx_lurk_requests = (ngx_atomic_t *) (shared + (i++) * cl);
        ngx_lurk_response_time = (ngx_atomic_t *) (shared + (i++) * cl);
        ngx_lurk_request_master_secret = (ngx_atomic_t *) (shared + (i++) * cl);
        ngx_lurk_request_sign = (ngx_atomic_t *) (shared + (i++) * cl);
        ngx_lurk_request_cert_verify = (ngx_atomic_t *) (shared + (i++) * cl);
        ngx_lurk_pkey_rsa = (ngx_atomic_t *) (shared + (i++) * cl);
        ngx_lurk_pkey_ecc = (ngx_atomic_t *) (shared + (i++) * cl);
        ngx_lurk_fail_requests = (ngx_atomic_t *) (shared + (i++) * cl);
        ngx_lurk_fail_no_key = (ngx_atomic_t *) (shared + (i++) * cl);
        ngx_lurk_fail_bad_format = (ngx_atomic_t *) (shared + (i++) * cl);
        ngx_lurk_fail_bad_version = (ngx_atomic_t *) (shared + (i++) * cl);
        ngx_lurk_fail_bad_type = (ngx_atomic_t *) (shared + (i++) * cl);
        ngx_lurk_fail_internal = (ngx_atomic_t *) (shared + (i++) * cl);
        ngx_lurk_fail_decrypt = (ngx_atomic_t *) (shared + (i++) * cl);
        ngx_lurk_fail_master_secret = (ngx_atomic_t *) (shared + (i++) * cl);
        ngx_lurk_fail_sign = (ngx_atomic_t *) (shared + (i++) * cl);
        ngx_lurk_fail_cert_verify = (ngx_atomic_t *) (shared + (i++) * cl);
        ngx_lurk_fail_write = (ngx_atomic_t *) (shared + (i++) * cl);
        ngx_lurk_fail_read = (ngx_atomic_t *) (shared + (i++) * cl);
        ngx_lurk_fail_rtimeout = (ngx_atomic_t *) (shared + (i++) * cl);
        ngx_lurk_fail_wtimeout = (ngx_atomic_t *) (shared + (i++) * cl);
        ngx_lurk_fail_unknown_msg = (ngx_atomic_t *) (shared + (i++) * cl);
        ngx_lurk_accepts = (ngx_atomic_t *) (shared + (i++) * cl);
        ngx_lurk_keepalives = (ngx_atomic_t *) (shared + (i++) * cl);
        ngx_lurk_stat_count = i;
    }

    return lcf;
}


static void
ngx_tcp_lurk_limit_keyid_handler(ngx_event_t *ev)
{
    ngx_lurk_limit_keyid_t  *val = ev->data;

    if (ev->timedout) {
        ev->timedout = 0;

        if (val->remain < val->limit) {
            ngx_add_timer(&val->ev, 1000);
        }

        val->remain = val->limit;

        return;
    }
}


static char *
ngx_tcp_lurk_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_tcp_lurk_main_conf_t   *mconf = conf;

    if (mconf->get_key_mode.len == 0) {
        mconf->remote = 0; // default must be local

    } else if (mconf->get_key_mode.len == (sizeof("local") - 1) &&
               ngx_strncmp("local", mconf->get_key_mode.data,
                            mconf->get_key_mode.len) == 0)
    {
        mconf->remote = 0;

    } else {
        return "invalid lurk_get_key_mode, must be local";
    }

    if (!mconf->remote) {
        return NGX_CONF_OK;
    }

    return NGX_CONF_OK;
}


static char *
ngx_tcp_lurk_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_uint_t               i, sl;
    ngx_keyval_t            *elts, *kv;
    ngx_hash_init_t          hash;
    ngx_pool_cleanup_t      *cln;
    ngx_tcp_lurk_conf_t     *prev = parent;
    ngx_tcp_lurk_conf_t     *conf = child;
    ngx_hash_keys_arrays_t   ha;
    ngx_lurk_limit_keyid_t  *val;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);

    if (!conf->enable) {
        return NGX_CONF_OK;
    }

    ngx_conf_merge_size_value(conf->buffer_size, prev->buffer_size,
                              (size_t) ngx_pagesize);

    ngx_conf_merge_msec_value(conf->send_timeout,
                              prev->send_timeout, 60000);

    ngx_conf_merge_msec_value(conf->read_timeout,
                              prev->read_timeout, 60000);

    ngx_conf_merge_msec_value(conf->keepalive_timeout,
                              prev->keepalive_timeout, 75000);

    ngx_conf_merge_uint_value(conf->keepalive_requests,
                              prev->keepalive_requests, 100);

    ngx_conf_merge_str_value(conf->pkey_path, prev->pkey_path, "");

    ngx_conf_merge_str_value(conf->status_uri, prev->status_uri,
                             NGX_TCP_LURK_STATUS_URI);

    sl = sizeof("GET  HTTP/1.0") + conf->status_uri.len;

    conf->status_req_line.data = ngx_pcalloc(cf->pool, sl);
    if (conf->status_req_line.data == NULL) {
        return NGX_CONF_ERROR;
    }

    conf->status_req_line.len = ngx_sprintf(conf->status_req_line.data,
                                "GET %V HTTP/1.0", &conf->status_uri)
                                - conf->status_req_line.data - 1;

    if (conf->pkey_path.len > 0) {
        ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
                               "load private keys failed from \"%V\"",
                               &conf->pkey_path);
        if (ngx_tcp_lurk_load_pkeys_from_file(cf, &conf->pkey_tree,
                                              &conf->pkey_queue,
                                              &conf->pkey_path) != NGX_OK) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "load private keys failed from \"%V\"",
                               &conf->pkey_path);

            return NGX_CONF_ERROR;
        }

        cln = ngx_pool_cleanup_add(cf->pool, 0);
        if (cln == NULL) {
            return NGX_CONF_ERROR;
        }

        cln->handler = ngx_tcp_lurk_cleanup_pkey;
        cln->data = conf;
    }

    hash.hash = &lurk_limit_keyid_runtime_tb;
    hash.key = ngx_hash_key_lc;
    hash.max_size = 1024;
    hash.bucket_size = 128;
    hash.name = "ngx_tcp_lurk_limit_keyid_runtime_hash";
    hash.pool = cf->pool;
    hash.temp_pool = cf->temp_pool;

    ha.pool = cf->pool;
    ha.temp_pool = cf->temp_pool;

    ngx_hash_keys_array_init(&ha, NGX_HASH_SMALL);

    if (conf->limit_keyid_arr) {
        elts = (ngx_keyval_t *)conf->limit_keyid_arr->elts;

        for (i = 0; i < conf->limit_keyid_arr->nelts; i++) {
            kv = &elts[i];

            val = ngx_pcalloc(cf->pool, sizeof (ngx_lurk_limit_keyid_t));
            if (val == NULL) {
                return "failed to allcate lurk limit keyid value";
            }

            val->limit = ngx_atoi(kv->value.data, kv->value.len);
            if (val->limit == NGX_ERROR) {
                return "invalid lurk limit keyid value";
            }

            val->remain = val->limit;

            val->ev.handler = ngx_tcp_lurk_limit_keyid_handler;
            val->ev.data = val;
            val->ev.log = cf->log;

            ngx_hash_add_key(&ha, &kv->key, val, 0);
        }
    }

    if (ngx_hash_init(&hash, ha.keys.elts, ha.keys.nelts) != NGX_OK) {
        return "failed to init limit keyid hash table";
    }

    return NGX_CONF_OK;
}


static void
ngx_tcp_lurk_set_keepalive(ngx_tcp_session_t *s)
{
    int                       tcp_nodelay;
    ngx_buf_t                *b;
    ngx_event_t              *rev, *wev;
    ngx_connection_t         *c;
    ngx_tcp_lurk_conf_t      *lcf;
    ngx_tcp_core_srv_conf_t  *cscf;

    c = s->connection;
    rev = c->read;

    lcf = ngx_tcp_get_module_srv_conf(s, ngx_tcp_lurk_module);
    cscf = ngx_tcp_get_module_srv_conf(s, ngx_tcp_core_module);

    ngx_log_debug0(NGX_LOG_DEBUG_TCP, c->log, 0,
                   "[tcp lurk]set tcp lurk keepalive handler");

    c->log->action = "closing tcp session";

    /* free tcp session's buffer */
    b = s->buffer;
    if (ngx_pfree(c->pool, b->start) == NGX_OK) {

        /*
         * the special note for ngx_tcp_lurk_keepalive_handler() that
         * c->buffer's memory was freed
         */

        b->pos = NULL;

    } else {
        b->pos = b->start;
        b->last = b->start;
    }

    if (ngx_handle_read_event(rev, 0) != NGX_OK) {
        ngx_tcp_close_connection(c);
        return;
    }

    wev = c->write;
    wev->handler = ngx_tcp_lurk_empty_handler;

#if (NGX_TCP_SSL)
    if (c->ssl) {
        ngx_ssl_free_buffer(c);
    }
#endif

    rev->handler = ngx_tcp_lurk_keepalive_handler;

    if (wev->active && (ngx_event_flags & NGX_USE_LEVEL_EVENT)) {
        if (ngx_del_event(wev, NGX_WRITE_EVENT, 0) != NGX_OK) {
            ngx_tcp_close_connection(c);
            return;
        }
    }

    c->log->action = "tcp lurk keepalive";

    if (c->tcp_nopush == NGX_TCP_NOPUSH_SET) {
        if (ngx_tcp_push(c->fd) == -1) {
            ngx_connection_error(c, ngx_socket_errno, ngx_tcp_push_n " failed");
            ngx_tcp_close_connection(c);
            return;
        }

        c->tcp_nopush = NGX_TCP_NOPUSH_UNSET;
        tcp_nodelay = ngx_tcp_nodelay_and_tcp_nopush ? 1 : 0;

    } else {
        tcp_nodelay = 1;
    }

    if (tcp_nodelay
        && cscf->tcp_nodelay
        && c->tcp_nodelay == NGX_TCP_NODELAY_UNSET)
    {
        ngx_log_debug0(NGX_LOG_DEBUG_TCP, c->log, 0, "[tcp lurk]tcp_nodelay");

        if (c->fd != (ngx_socket_t) -1
            && setsockopt(c->fd, IPPROTO_TCP, TCP_NODELAY,
                       (const void *) &tcp_nodelay, sizeof(int)) == -1)
        {
#if (NGX_SOLARIS)
            /* Solaris returns EINVAL if a socket has been shut down */
            c->log_error = NGX_ERROR_IGNORE_EINVAL;
#endif

            ngx_connection_error(c, ngx_socket_errno,
                                 "setsockopt(TCP_NODELAY) failed");

            c->log_error = NGX_ERROR_INFO;
            ngx_tcp_close_connection(c);
            return;
        }

        c->tcp_nodelay = NGX_TCP_NODELAY_SET;
    }

    c->idle = 1;
    ngx_reusable_connection(c, 1);

    ngx_add_timer(rev, lcf->keepalive_timeout);

    if (rev->ready) {
        ngx_post_event(rev, &ngx_posted_events);
    }
}


static void
ngx_tcp_lurk_keepalive_handler(ngx_event_t *rev)
{
    size_t              size;
    ssize_t             n;
    ngx_buf_t          *b;
    ngx_connection_t   *c;
    ngx_tcp_session_t  *s;

    c = rev->data;
    s = c->data;

    ngx_log_debug0(NGX_LOG_DEBUG_TCP, c->log, 0,
                   "[tcp lurk]tcp lurk keepalive handler");

    if (rev->timedout || c->close) {
        if (rev->timedout) {
            rev->timedout = 0;
        }

        ngx_tcp_close_connection(c);
        return;
    }

#if (NGX_HAVE_KQUEUE)

    if (ngx_event_flags & NGX_USE_KQUEUE_EVENT) {
        if (rev->pending_eof) {
            c->log->handler = NULL;
            ngx_log_error(NGX_LOG_INFO, c->log, rev->kq_errno,
                          "kevent() reported that client %V closed "
                          "keepalive connection", &c->addr_text);
#if (NGX_TCP_SSL)
            if (c->ssl) {
                c->ssl->no_send_shutdown = 1;
            }
#endif
            ngx_tcp_close_connection(c);
            return;
        }
    }

#endif

    b = s->buffer;
    size = b->end - b->start;

    if (b->pos == NULL) {

        /*
         * The s->buffer's memory was freed by
         * ngx_tcp_lurk_set_keepalive().
         * However, the c->buffer->start and c->buffer->end were not changed
         * to keep the buffer size.
         */

        b->pos = ngx_palloc(c->pool, size);
        if (b->pos == NULL) {
            ngx_tcp_close_connection(c);
            return;
        }

        b->start = b->pos;
        b->last = b->pos;
        b->end = b->pos + size;
    }

    c->log_error = NGX_ERROR_IGNORE_ECONNRESET;
    ngx_set_socket_errno(0);

    n = c->recv(c, b->last, size);
    c->log_error = NGX_ERROR_INFO;

    if (n == NGX_AGAIN) {
        if (ngx_handle_read_event(rev, 0) != NGX_OK) {
            ngx_tcp_close_connection(c);
            return;
        }

        /*
         * Like ngx_tcp_lurk_set_keepalive() we are trying to not hold
         * c->buffer's memory for a keepalive connection.
         */

        if (ngx_pfree(c->pool, b->start) == NGX_OK) {

            /*
             * the special note that c->buffer's memory was freed
             */

            b->pos = NULL;
        }

        return;
    }

    if (n == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, c->log, ngx_socket_errno,
                "ngx tcp lurk read fail n %d in keepalive handler", n);
        ngx_tcp_close_connection(c);
        return;
    }

    c->log->handler = NULL;

    if (n == 0) {
        ngx_log_error(NGX_LOG_INFO, c->log, ngx_socket_errno,
                      "client %V closed keepalive connection", &c->addr_text);
        ngx_tcp_close_connection(c);
        return;
    }

    b->last += n;

    c->log->handler = ngx_tcp_log_error;
    c->log->action = "reading client lurk request";

    c->idle = 0;
    ngx_reusable_connection(c, 0);

    c->sent = 0;
    c->destroyed = 0;

    ngx_del_timer(rev);

    /* re-init tcp session */
    ngx_tcp_lurk_reinit_connection(c);
}


static void
ngx_tcp_lurk_finalize_session(ngx_tcp_session_t *s, ngx_int_t success)
{
    uint64_t              elpased = 0;
    struct timeval        end_tv;
    ngx_connection_t     *c = s->connection;
    ngx_tcp_lurk_ctx_t   *ctx;
    ngx_tcp_lurk_conf_t  *lcf;

    lcf = ngx_tcp_get_module_srv_conf(s, ngx_tcp_lurk_module);

    ctx = ngx_tcp_get_module_ctx(s, ngx_tcp_lurk_module);

    if (ctx) {
        ctx->in_process = 0;
    }

    // 本地加载秘钥时,不能释放pkey
    if (lcf->pkey_path.len == 0 && ctx && ctx->evp_pkey) {
        EVP_PKEY_free(ctx->evp_pkey);
        ctx->evp_pkey = NULL;
    }

    if (c->read->timer_set && !c->read->timedout) {
        ngx_del_timer(c->read);
    }

    if (c->write->timer_set && !c->write->timedout) {
        ngx_del_timer(c->write);
    }

    ngx_gettimeofday(&end_tv);

    if (ctx) {
        elpased = (end_tv.tv_sec - ctx->start_tv.tv_sec) * 1000000ULL
                        + (end_tv.tv_usec - ctx->start_tv.tv_usec);
        elpased /= 1000;
    }

    ngx_lurk_log_error(NGX_LOG_NOTICE, s->connection->log, 0,
                       "keyserver lurk elapsed:%uLms, success:%i",
                       elpased, success);

    if (!ngx_terminate
         && !ngx_exiting
         && lcf->keepalive_timeout > 0
         && --s->keepalive_requests > 0
         && success)
    {
        ngx_tcp_log_handler(s);
        ngx_tcp_lurk_set_keepalive(s);
        return;
    }

    ngx_tcp_finalize_session(s);
}


void hex2bin(const char *hex, size_t len, uint8_t *bin)
{
    size_t  i;

    assert(len % 2 == 0);

    for (i = 0; i < len; i += 2) {
        bin[i/2] = hex2i(hex[i]) * 16 + hex2i(hex[i + 1]);
    }

    return;
}


ngx_tcp_lurk_key_node_t *
ngx_tcp_lurk_shm_find_key(ngx_rbtree_t *key_tree, const uint8_t *key_id)
{
    ngx_int_t                 rc;
    ngx_rbtree_key_t          rbtree_key;
    ngx_rbtree_node_t        *node = key_tree->root;
    ngx_rbtree_node_t        *sentinel = key_tree->sentinel;
    ngx_tcp_lurk_key_node_t  *p;

    rbtree_key = ngx_crc32_short((u_char *)key_id, NGX_TCP_LURK_KEY_ID_LEN);

    while (node != sentinel) {

        if (rbtree_key < node->key) {
            node = node->left;
            continue;
        }

        if (rbtree_key > node->key) {
            node = node->right;
            continue;
        }

        /* hash == node->key */
        p = (ngx_tcp_lurk_key_node_t *) node;

        /* TODO: optimize this */
        rc = ngx_memcmp(key_id, p->key_id, NGX_TCP_LURK_KEY_ID_LEN);

        if (rc == 0) {
            return p;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    /* not found */
    return NULL;
}


static int hex2i(char ch)
{
    if (ch >= '0' && ch <='9') {
        return ch - '0';
    }

    if (ch >= 'a' && ch <= 'f') {
        return ch - 'a' + 10;
    }

    if (ch >= 'A' && ch <= 'F') {
        return ch - 'A' + 10;
    }

    return 0;
}


static ngx_int_t
ngx_tcp_lurk_init_module(ngx_cycle_t *cf)
{
    (void)cf;

//#if OPENSSL_VERSION_NUMBER < 0x10100003L
    ngx_tcp_lurk_load_ssl_method();
//#endif

    return NGX_OK;

}
