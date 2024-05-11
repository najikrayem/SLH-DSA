#include <string.h>

#include "slh_keygen.h"
#include "random.h"
#include "slh_common.h"

#if DEBUG_ENABLED
#include <stdio.h>
#endif

void slh_keygen(SK* out_sk, PK* out_pk){


    #if DEBUG_ENABLED
        printf("slh_keygen will not use random seeds for testing purposes\n");
        // fill with all zeros instead
        memset(out_sk->seed, 0, SLH_PARAM_n);
        memset(out_sk->prf, 0, SLH_PARAM_n);
        memset(out_pk->seed, 0, SLH_PARAM_n);
    #else
        randBytes(out_sk->seed, SLH_PARAM_n);
        randBytes(out_sk->prf,  SLH_PARAM_n);
        randBytes(out_pk->seed, SLH_PARAM_n);
    #endif

    // TODO NK
    #if DEBUG_ENABLED
        printf("For generating the keys, the following random seeds were used (hex):\n");
        printf("\tSK seed: ");
        for (int i = 0; i < SLH_PARAM_n; i++) {
            printf("0x%02x ", out_sk->seed[i]);
        }
        printf("\n");
        printf("\tPR seed: ");
        for (int i = 0; i < SLH_PARAM_n; i++) {
            printf("0x%02x ", out_sk->prf[i]);
        }
        printf("\n");
        printf("\tPK seed: ");
        for (int i = 0; i < SLH_PARAM_n; i++) {
            printf("0x%02x ", out_pk->seed[i]);
        }
        printf("\n");
    #endif


    ADRS adrs = {0};
    setLayerAddress(&adrs, SLH_PARAM_d - 1);

    xmss_node(out_sk->seed, 0, SLH_PARAM_hprime, out_pk->seed, &adrs, out_pk->root);

    // TODO NK
    memcpy(&(out_sk->pk), out_pk, SLH_PARAM_pk_bytes);

}