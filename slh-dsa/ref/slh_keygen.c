#include "slh_keygen.h"
#include "slh_common.h"

#include "random.h"

void slh_keygen(SK* out_sk, PK* out_pk){

    randBytes(out_sk->seed, SLH_PARAM_n);
    randBytes(out_sk->prf,  SLH_PARAM_n);
    randBytes(out_pk->seed, SLH_PARAM_n);

    ADRS adrs = {0};
    setLayerAddress(&adrs, SLH_PARAM_d - 1);

    xmss_node(out_sk->seed, 0, SLH_PARAM_hprime, out_pk->seed, &adrs, out_pk->root);

    memcopy(out_sk->pk, out_pk, SLH_PARAM_pk_bytes);

}