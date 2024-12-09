
## Description

alibabacloud-dcdn-keyserver is an implementation aliyun CDN's Keyless SSL Protocol.

## Before building from git
When build from git, run the following command to pull submodules:

```shell
$ git submodule update --init
```

## Building
```shell
$ patch -p1 -d deps/nginx_tcp_proxy_module/ < tcp_module_compile_fixed.patch
$ patch -p1 -d deps/nginx_tcp_proxy_module/ < tcp_lurk_keepalive.patch
$ patch -p1 -d deps/nginx_tcp_proxy_module/ < tcp_access_log_format.patch
$ patch -p1 -d deps/OpenSSL_1_1_1-stable/ < lurk_openssl_1_1_1-stable.patch

$ wget 'https://nginx.org/download/nginx-1.26.2.tar.gz'
$ tar -xzvf nginx-1.26.2.tar.gz
$ patch -p1 -d nginx-1.26.2 < deps/nginx_tcp_proxy_module/tcp.patch

$ cd nginx-1.26.2
$ ./configure \
    --with-http_ssl_module \
    --with-openssl=../deps/OpenSSL_1_1_1-stable \
    --add-module=../deps/nginx_tcp_proxy_module \
    --add-module=.. \
    --with-cc-opt="-Wno-implicit-fallthrough"

$ make
```


## Configure
1. create a certificate for keyless channel communication
```shell
# vi openssl.conf
[ req ]
default_bits = 2048
encrypt_key = no
distinguished_name = req_distinguished_name
[ req_distinguished_name ]

# gen crt/key
openssl req -x509 -new -config ./openssl.conf -subj /CN=CN/ -out example-keyless-server.pem -keyout example-keyless-server.key
```

2. example of keyless server configure
``` conf
# example of config

user root;
worker_processes  auto;

error_log  logs/error.log;

#pid        logs/nginx.pid;

events {
    worker_connections  1024;
}

tcp {

    log_format  main '{"time":$lurk_start_time,"client_ip":"$client_ip","server_ip":"$host_ip","lurk_id":$lurk_id,"lurk_type":$lurk_type,"lurk_error":$lurk_err_code}';
    access_log  /usr/local/nginx/logs/lurk_access.log main;

    lurk_get_key_mode local;

    server {

        listen  8443 ssl;

        ssl_certificate         /usr/local/nginx/conf/example-keyless-server.pem;
        ssl_certificate_key     /usr/local/nginx/conf/example-keyless-server.key;

        ssl_protocols TLSv1.2;
        ssl_ciphers   EECDH+AES256;

        ssl_session_cache shared:lurk:100m;
        ssl_session_timeout 8h;

        ssl_prefer_server_ciphers on;

        lurk;
        lurk_pkey_path /usr/local/nginx/conf/pkeys;
        lurk_keepalive_requests  1000;
    }
}

http {
    include       mime.types;
    default_type  application/octet-stream;

    #log_format  main  '$remote_addr - $remote_user [$time_local] "$request" '
    #                  '$status $body_bytes_sent "$http_referer" '
    #                  '"$http_user_agent" "$http_x_forwarded_for"';

    #access_log  logs/access.log  main;

    sendfile        on;
    #tcp_nopush     on;

    #keepalive_timeout  0;
    keepalive_timeout  65;

    #gzip  on;


    server {
        listen       80;
        server_name  localhost;

        #charset koi8-r;

        #access_log  logs/host.access.log  main;

        location / {
            root   html;
            index  index.html index.htm;
        }

        #error_page  404              /404.html;

        # redirect server error pages to the static page /50x.html
        #
        error_page   500 502 503 504  /50x.html;
        location = /50x.html {
            root   html;
        }

    }
}

```

## Directives

### lurk server
#### lurk_get_key_mode
Syntax: lurk_get_key_mode local;

Context: tcp

```
lurk_get_key_mode local;
```

#### lurk
Syntax: lurk;

Context: tcp, server

```
lurk;
```

#### lurk_pkey_path
Syntax: lurk_pkey_path path;

Context: tcp, server

```
lurk_pkey_path /usr/local/nginx/conf/pkeys;
```

#### lurk_keepalive_requests
Syntax: lurk_keepalive_requests number;

Context: tcp, server

```
lurk_keepalive_requests 1000;
```

### Access log

#### access_log
Syntax: access_log off|path [format_name]

Context: tcp

Sets access log parameters. See `log_format` directive for more details about formats.

```
access_log  /usr/local/nginx/logs/lurk_access.log main;
```

#### log_format
Syntax: log_format format_name format;

Context: tcp

Creates named log format similar to Nginx HTTP log formats. Several variables are supported within log format:
* lurk_start_time
* lurk_id
* lurk_pkey_id
* lurk_sni
* lurk_type
* lurk_client_ip
* lurk_err_code

```
log_format  main '{"time":$lurk_start_time,"client_ip":"$client_ip","server_ip":"$host_ip","lurk_id":$lurk_id,"lurk_type":$lurk_type,"lurk_error":$lurk_err_code}';
```
