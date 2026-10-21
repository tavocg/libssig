# Roadmap

El objetivo es tener una interfaz similar a esta:

```c
typedef enum {
    LIBSSIG_TYPE_PDF,
    LIBSSIG_TYPE_JSON,
    LIBSSIG_TYPE_XML,
    LIBSSIG_TYPE_TEXT,
    LIBSSIG_TYPE_BINARY,
} libssig_type;

typedef enum {
    LIBSSIG_ALGO_RSA_PKCS,
    LIBSSIG_ALGO_RSA_PSS,
    LIBSSIG_ALGO_ECDSA,
    //...
} libssig_algo;

typedef enum {
    LIBSSIG_HASH_NONE,
    LIBSSIG_HASH_SHA256,
    LIBSSIG_HASH_SHA384,
    LIBSSIG_HASH_SHA512,
    LIBSSIG_HASH_SHA3_256,
    //...
} libssig_hash;

typedef enum {
    LIBSSIG_FORMAT_CADES,
    // Luego...
    LIBSSIG_FORMAT_PADES,
    //LIBSSIG_FORMAT_XADES,
    //LIBSSIG_FORMAT_JADES,
} libssig_format;

typedef enum {
    LIBSSIG_LEVEL_B_LTA = 0,
    LIBSSIG_LEVEL_B_B,
    LIBSSIG_LEVEL_B_T,
    LIBSSIG_LEVEL_B_LT,
} libssig_level;

typedef struct {
    const unsigned char* data;
    size_t               data_len;
    libssig_type         type; // Optional

    const char*          uri;    // Optional
    const char*          pin;    // Optional
    const unsigned char* id;     // Optional
    size_t               id_len; // Optional

    libssig_algo    algo;    // Optional
    libssig_hash    hash;    // Optional
    libssig_format  format;  // Optional
    libssig_profile profile; // Optional
} libssig_sign_params;

typedef struct {
    unsigned char* signature;
    size_t         signature_len;
    unsigned long  ck_rv;
} libssig_sign_result;

int libssig_sign(
    const libssig_sign_params* params,
    libssig_sign_result*       result
);
```

Notemos que, al igual que la interfaz de CLI, podemos auto-seleccionar
varios campos. Su uso:

```sh
sign FILE...
     [-c CONFIG] [-T TYPE] [-o FILE]
     -p PROFILE

sign FILE...
     [-c CONFIG] [-T TYPE] [-o FILE] [-A TSA_URL]
     [-t URI] [-P PIN] [-k ID]
     [-a ALGORITHM] [-H HASH]
     [-f FORMAT] [-l LEVEL]
```

`-p profile` permitiría seleccionar un perfil de la config.
`-A TSA_URL` seleccionaría la autoridad de sellado de tiempo mediante la URL
de su servicio RFC 3161, por ejemplo `-A https://tsa.example/timestamp`.
Al usar `-p PROFILE`, la TSA se definiría dentro del perfil, sin `-A` en esa
forma de uso.
El transporte HTTP y la configuración de confianza de esa TSA corresponderían
a la aplicación. `-T TYPE` conserva la selección del tipo de contenido.
Además, idealmente la config permitiría `pincmd` y todas las opciones
tendrían su variable de entorno correspondiente (tienen prioridad los
argumentos).

## TODO

Para conseguir esto, se requiere lo siguiente:

- [X] `p11-kit` ya tiene `pkcs11-tool --module /path/to/pkcs11.so -T`, que
      expone información del token, como su URI. El objetivo es exponer un
      método `libssig_tokens` que básicamente funcione igual. La implementación
      de CLI lo expondría mediante `sign tokens`, pero idealmente permitiría
      `--info label,model,flags,...etc` y también `--json`. Por defecto lista
      únicamente URIs y usa los módulos que encuentre `p11-kit`.
- [X] Firmado CAdES y PAdES con:
      - `-a RSA` (RSA PKCS#1 v1.5)
      - `-H SHA256`
      - `-l B-LTA`
      Los argumentos son case insensitive.
      Para conseguir esto, el módulo debe exponer `libssig_sign`.
- [ ] `libssig_verify`. Con el objetivo de `sign verify FILES...`

Los niveles de generación B-B, B-T, B-LT y B-LTA están implementados para
CAdES y PAdES; LTA es el valor por defecto. Los servicios de red los aporta
la aplicación mediante `libssig_sign_services`. Sign selecciona el nivel con
`-l` y el formato con `-f`; ver [profiles.md](profiles.md) para límites actuales.

`libssig_verify` detecta las evidencias y selecciona la política por defecto;
B-LTA usa validación histórica acotada. `LIBSSIG_VERIFY_HISTORICAL` permite
exigirla incluso cuando faltan evidencias de archivo. La renovación de sellos y la
política ETSI completa de validación temporal siguen pendientes; los límites
y la entrada de revocación actual están descritos en [profiles.md](profiles.md).
