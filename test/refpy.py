#   slh_dsa.py
#   2023-11-24  Markku-Juhani O. Saarinen < mjos@iki.fi>. See LICENSE

from Crypto.Hash import SHAKE256, SHA256, SHA512
import os
#   A class for handling Addresses (Section 4.2.)

class ADRS:
    #   type constants
    WOTS_HASH   = 0
    WOTS_PK     = 1
    TREE        = 2
    FORS_TREE   = 3
    FORS_ROOTS  = 4
    WOTS_PRF    = 5
    FORS_PRF    = 6

    def __init__(self, a=32):
        """Initialize."""
        self.a = bytearray(a)

    def copy(self):
        """ Make a copy of self."""
        return ADRS(self.a)

    def set_layer_address(self, x):
        """ Set layer address."""
        self.a[ 0: 4] = x.to_bytes(4, byteorder='big')

    def set_tree_address(self, x):
        """ Set tree address."""
        self.a[ 4:16] = x.to_bytes(12, byteorder='big')

    def set_key_pair_address(self, x):
        """ Set key pair Address."""
        self.a[20:24] = x.to_bytes(4, byteorder='big')

    def get_key_pair_address(self):
        """ Get key pair Address."""
        return int.from_bytes(self.a[20:24], byteorder='big')

    def set_tree_height(self, x):
        """ Set FORS tree height."""
        self.a[24:28] = x.to_bytes(4, byteorder='big')

    def set_chain_address(self, x):
        """ Set WOTS+ chain address."""
        self.a[24:28] = x.to_bytes(4, byteorder='big')

    def set_tree_index(self, x):
        """ Set FORS tree index."""
        self.a[28:32] = x.to_bytes(4, byteorder='big')

    def get_tree_index(self):
        """ Get FORS tree index."""
        return int.from_bytes(self.a[28:32], byteorder='big')

    def set_hash_address(self, x):
        """ Set WOTS+ hash address."""
        self.a[28:32] = x.to_bytes(4, byteorder='big')

    def set_type_and_clear(self, t):
        """ The member function ADRS.setTypeAndClear(Y) for addresses sets
            the type of the ADRS to Y and sets the fnal 12 bytes of the ADRS
            to zero."""
        self.a[16:20] = t.to_bytes(4, byteorder='big')
        for i in range(12):
            self.a[20 + i] = 0

    def adrs(self):
        """ Return the ADRS as bytes."""
        return self.a

    def adrsc(self):
        """ Compressed address ADRDc used with SHA-2."""
        return self.a[3:4] + self.a[8 : 16] + self.a[19:20] + self.a[20:32]


#   SLH-DSA Implementation

class SLH_DSA:

    #   initialize
    def __init__(self,  hashname='SHAKE', paramid='f', n=16, h=66,
                        d=22, hp=3, a=6, k=33, lg_w=4, m=34, rbg=None):
        self.hashname   = hashname
        self.paramid    = paramid
        self.n          = n
        self.h          = h
        self.d          = d
        self.hp         = hp
        self.a          = a
        self.k          = k
        self.lg_w       = lg_w
        self.m          = m
        self.rbg        = rbg
        self.algname    = 'SPHINCS+'
        self.stdname    = f'SLH-DSA-{self.hashname}-{8*self.n}{self.paramid}'

        #   instantiate hash functions
        if hashname == 'SHAKE':
            self.h_msg      = self.shake_h_msg
            self.prf        = self.shake_prf
            self.prf_msg    = self.shake_prf_msg
            self.h_f            = self.shake_f
            self.h_h            = self.shake_f
            self.h_t            = self.shake_f
        elif hashname == 'SHA2' and self.n == 16:
            self.h_msg      = self.sha256_h_msg
            self.prf        = self.sha256_prf
            self.prf_msg    = self.sha256_prf_msg
            self.h_f            = self.sha256_f
            self.h_h            = self.sha256_f
            self.h_t            = self.sha256_f
        elif hashname == 'SHA2' and self.n > 16:
            self.h_msg      = self.sha512_h_msg
            self.prf        = self.sha256_prf
            self.prf_msg    = self.sha512_prf_msg
            self.h_f            = self.sha256_f
            self.h_h            = self.sha512_h
            self.h_t            = self.sha512_h

        #   equations 5.1 - 5.4
        self.w      = 2**self.lg_w
        self.len1   = (8 * self.n + (self.lg_w - 1)) // self.lg_w
        self.len2   = (self.len1 *
                        (self.w - 1)).bit_length() // self.lg_w + 1
        self.len    = self.len1 + self.len2

        #   external parameter sizes
        self.pk_sz      = 2 * self.n
        self.sk_sz      = 4 * self.n
        self.sig_sz     = (1 + self.k*(1 + self.a) + self.h +
                            self.d * self.len) * self.n

    def set_random(self, rbg):
        """Set the key material RBG."""
        self.rbg   =   rbg

    #   10.1.   SLH-DSA Using SHAKE
    def shake256(self, x, l):
        """SHAKE256(x, l): Internal hook."""
        return SHAKE256.new(x).read(l)

    def shake_h_msg(self, r, pk_seed, pk_root, m):
        return self.shake256(r + pk_seed + pk_root + m, self.m)

    def shake_prf(self, pk_seed, sk_seed, adrs):
        return self.shake256(pk_seed + adrs.adrs() + sk_seed, self.n)

    def shake_prf_msg(self, sk_prf, opt_rand, m):
        return self.shake256(sk_prf + opt_rand + m, self.n)

    def shake_f(self, pk_seed, adrs, m1):
        return self.shake256(pk_seed + adrs.adrs() + m1, self.n)

    #   Various constructions required for SHA-2 variants.

    def sha256(self, x, n=32):
        """Tranc_n(SHA2-256(x))."""
        return SHA256.new(x).digest()[0:n]

    def sha512(self, x, n=64):
        """Tranc_n(SHA2-512(x))."""
        return SHA512.new(x).digest()[0:n]

    def mgf(self, hash_f, hash_l, mgf_seed, mask_len):
        """NIST SP 800-56B REV. 2 / The Mask Generation Function (MGF)."""
        t = b''
        for c in range((mask_len + hash_l - 1) // hash_l):
            t += hash_f(mgf_seed + c.to_bytes(4, byteorder='big'))
        return t[0:mask_len]

    def mgf_sha256(self, mgf_seed, mask_len):
        """MGF1-SHA1-256(mgfSeed, maskLen)."""
        return self.mgf(self.sha256, 32, mgf_seed, mask_len)

    def mgf_sha512(self, mgf_seed, mask_len):
        """MGF1-SHA1-512(mgfSeed, maskLen)."""
        return self.mgf(self.sha512, 64, mgf_seed, mask_len)

    def hmac(self, hash_f, hash_l, hash_b, k, text):
        """FIPS PUB 198-1 HMAC."""
        if len(k) > hash_b:
            k = hash_f(k)
        ipad = bytearray(hash_b)
        ipad[0:len(k)] = k
        opad = bytearray(ipad)
        for i in range(hash_b):
            ipad[i] ^= 0x36
            opad[i] ^= 0x5C
        return hash_f(opad + hash_f(ipad + text))

    def hmac_sha256(self, k, text, n=32):
        """Trunc_n(HMAC-SHA-256(k, text)): Internal hook."""
        return self.hmac(self.sha256, 32, 64, k, text)[0:n]

    def hmac_sha512(self, k, text, n=64):
        """Trunc_n(HMAC-SHA-256(k, text)): Internal hook."""
        return self.hmac(self.sha512, 64, 128, k, text)[0:n]

    #   10.2    SLH-DSA Using SHA2 for Security Category 1

    def sha256_h_msg(self, r, pk_seed, pk_root, m):
        return self.mgf_sha256( r + pk_seed +
                self.sha256(r + pk_seed + pk_root + m), self.m)

    def sha256_prf(self, pk_seed, sk_seed, adrs):
        return self.sha256(pk_seed + bytes(64 - self.n) +
                                adrs.adrsc() + sk_seed, self.n)

    def sha256_prf_msg(self, sk_prf, opt_rand, m):
        return self.hmac_sha256(sk_prf, opt_rand + m, self.n)

    def sha256_f(self, pk_seed, adrs, m1):
        return self.sha256(pk_seed + bytes(64 - self.n) +
                            adrs.adrsc() + m1, self.n)

    #   10.3    SLH-DSA Using SHA2 for Security Categories 3 and 5

    def sha512_h_msg(self, r, pk_seed, pk_root, m):
        return self.mgf_sha512( r + pk_seed +
                self.sha512(r + pk_seed + pk_root + m), self.m)

    def sha512_prf_msg(self, sk_prf, opt_rand, m):
        return self.hmac_sha512(sk_prf, opt_rand + m, self.n)

    def sha512_h(self, pk_seed, adrs, m2):
        return self.sha512(pk_seed + bytes(128 - self.n) +
                            adrs.adrsc() + m2, self.n)

    #   --- FIPS 205 IPD Algorithms

    def to_int(self, s, n):
        """ Algorithm 1: toInt(X, n). Convert a byte string to an integer."""
        t = 0
        for i in range(n):
            t = (t << 8) + int(s[i])
        return t

    def to_byte(self, x, n):
        """ Algorithm 2: toByte(x, n). Convert an integer to a byte string."""
        t = x
        s = bytearray(n)
        for i in range(n):
            s[n - 1 - i] = t & 0xFF
            t >>= 8
        return s

    def base_2b(self, s, b, out_len):
        """ Algorithm 3: base_2b (X, b, out_len).
            Compute the base 2**b representation of X."""
        i = 0               # in
        c = 0               # bits
        t = 0               # total
        v = []              # baseb
        m = (1 << b) - 1    # mask
        for j in range(out_len):
            while c < b:
                t = (t << 8) + int(s[i])
                i += 1
                c += 8
            c -= b
            v += [ (t >> c) & m ]
        return v

    def chain(self, x, i, s, pk_seed, adrs):
        """ Algorithm 4: chain(X, i, s, PK.seed, ADRS).
            Chaining function used in WOTS+."""
        if i + s >= self.w:
            return None
        t = x
        for j in range(i, i + s):
            adrs.set_hash_address(j)
            t = self.h_f(pk_seed, adrs, t)
        return t

    def wots_pkgen(self, sk_seed, pk_seed, adrs):
        """ Algorithm 5: wots_PKgen(SK.seed, PK.seed, ADRS).
            Generate a WOTS+ public key."""
        sk_adrs = adrs.copy()
        sk_adrs.set_type_and_clear(ADRS.WOTS_PRF)
        sk_adrs.set_key_pair_address(adrs.get_key_pair_address())
        tmp = b''
        for i in range(self.len):
            sk_adrs.set_chain_address(i)
            sk = self.prf(pk_seed, sk_seed, sk_adrs)
            adrs.set_chain_address(i)
            tmp += self.chain(sk, 0, self.w - 1, pk_seed, adrs)
        wotspk_adrs = adrs.copy()
        wotspk_adrs.set_type_and_clear(ADRS.WOTS_PK)
        wotspk_adrs.set_key_pair_address(adrs.get_key_pair_address())
        pk = self.h_t(pk_seed, wotspk_adrs, tmp)
        return pk

    def wots_sign(self, m, sk_seed, pk_seed, adrs):
        """ Algorithm 6: wots_sign(M, SK.seed, PK.seed, ADRS).
            Generate a WOTS+ signature on an n-byte message."""
        csum    =   0
        msg     =   self.base_2b(m, self.lg_w, self.len1)
        print(msg)
        for i in range(self.len1):
            csum    +=  self.w - 1 - msg[i]

        print(csum)
        csum    <<= ((8 - ((self.len2 * self.lg_w) % 8)) % 8)
        print(csum)

        sumval = (self.len2 * self.lg_w + 7) // 8
        print(sumval)

        csum_bytes = self.to_byte(csum, sumval)
        for i in csum_bytes:
            print(i, end=' ')
        print()

        msg     +=  self.base_2b(csum_bytes, self.lg_w, self.len2)

        print(msg)

        sk_adrs = adrs.copy()
        sk_adrs.set_type_and_clear(ADRS.WOTS_PRF)
        sk_adrs.set_key_pair_address(adrs.get_key_pair_address())
        sig = b''
        for i in range(self.len):
            sk_adrs.set_chain_address(i)
            sk = self.prf(pk_seed, sk_seed, sk_adrs)
            adrs.set_chain_address(i)
            sig_addition = self.chain(sk, 0, msg[i], pk_seed, adrs)
            sig += sig_addition

            print("WOTS+ Signature: For Loop, i = " + str(i))
            print("WOTS+ Signature: sk = ", end='')
            for x in sk:
                print(x, end=", ")
            print()

            print("WOTS+ Signature: msg[i] = " + str(msg[i]))

            print("WOTS+ Signature: sig_out = ", end='')
            for x in sig_addition:
                print(x, end=", ")
            print()
            print()
            

        print()
        for x in sig:
            print(x, end=' ')
        print()

        return sig

    def wots_pk_from_sig(self, sig, m, pk_seed, adrs):
        """ Algorithm 7: wots_PKFromSig(sig, M, PK.seed, ADRS).
            Compute a WOTS+ public key from a message and its signature."""
        csum    =   0
        msg     =   self.base_2b(m, self.lg_w, self.len1)
        for i in range(self.len1):
            csum    +=  self.w - 1 - msg[i]
        csum    <<= ((8 - ((self.len2 * self.lg_w) % 8)) % 8)
        msg     +=  self.base_2b(self.to_byte(csum,
            (self.len2 * self.lg_w + 7) // 8), self.lg_w, self.len2)
        tmp     =   b''
        for i in range(self.len):
            adrs.set_chain_address(i)
            tmp +=  self.chain(sig[i*self.n:(i+1)*self.n],
                                msg[i], self.w - 1 - msg[i],
                                pk_seed, adrs)
        wots_pk_adrs    = adrs.copy()
        wots_pk_adrs.set_type_and_clear(ADRS.WOTS_PK)
        wots_pk_adrs.set_key_pair_address(adrs.get_key_pair_address())
        pk_sig  =   self.h_t(pk_seed, wots_pk_adrs, tmp)
        return  pk_sig

    def xmss_node(self, sk_seed, i, z, pk_seed, adrs):
        """ Algorithm 8: xmss_node(SK.seed, i, z, PK.seed, ADRS).
            Compute the root of a Merkle subtree of WOTS+ public keys."""
        if z > self.hp or i >= 2**(self.hp -  z):
            return None
        if z == 0:
            adrs.set_type_and_clear(ADRS.WOTS_HASH)
            adrs.set_key_pair_address(i)
            node = self.wots_pkgen(sk_seed, pk_seed, adrs)
        else:
            lnode = self.xmss_node(sk_seed, 2 * i, z - 1, pk_seed, adrs)
            rnode = self.xmss_node(sk_seed, 2 * i + 1, z - 1, pk_seed, adrs)
            adrs.set_type_and_clear(ADRS.TREE)
            adrs.set_tree_height(z)
            adrs.set_tree_index(i)
            node = self.h_h(pk_seed, adrs, lnode + rnode)
        return node

    def xmss_sign(self, m, sk_seed, idx, pk_seed, adrs):
        """ Algorithm 9: xmss_sign(M, SK.seed, idx, PK.seed, ADRS).
            Generate an XMSS signature."""
        auth = b''
        for j in range(self.hp):
            k = (idx >> j) ^ 1
            auth += self.xmss_node(sk_seed, k, j, pk_seed, adrs)
        adrs.set_type_and_clear(ADRS.WOTS_HASH)
        adrs.set_key_pair_address(idx)
        sig = self.wots_sign(m, sk_seed, pk_seed, adrs)
        sig_xmss = sig + auth
        return sig_xmss

    def xmss_pk_from_sig(self, idx, sig_xmss, m, pk_seed, adrs):
        """ Algorithm 10: xmss_PKFromSig(idx, SIG_XMSS, M, PK.seed, ADRS).
            Compute an XMSS public key from an XMSS signature."""
        adrs.set_type_and_clear(ADRS.WOTS_HASH)
        adrs.set_key_pair_address(idx)
        sig     = sig_xmss[0:self.len*self.n]
        auth    = sig_xmss[self.len*self.n:]
        node_0  = self.wots_pk_from_sig(sig, m, pk_seed, adrs)

        adrs.set_type_and_clear(ADRS.TREE)
        adrs.set_tree_index(idx)
        for k in range(self.hp):
            adrs.set_tree_height(k + 1)
            auth_k = auth[k*self.n:(k+1)*self.n]
            if (idx >> k) & 1 == 0:
                adrs.set_tree_index(adrs.get_tree_index() // 2)
                node_1  = self.h_h(pk_seed, adrs, node_0 + auth_k)
            else:
                adrs.set_tree_index((adrs.get_tree_index() - 1) // 2)
                node_1  = self.h_h(pk_seed, adrs, auth_k + node_0)
            node_0 = node_1

        return node_0

    def ht_sign(self, m, sk_seed, pk_seed, i_tree, i_leaf):
        """ Algorithm 11: ht_sign(M, SK.seed, PK.seed, idx_tree, idx_leaf).
            Generate a hypertree signature."""
        adrs    = ADRS()
        adrs.set_tree_address(i_tree)
        sig_tmp = self.xmss_sign(m, sk_seed, i_leaf, pk_seed, adrs)
        sig_ht  = sig_tmp
        root    = self.xmss_pk_from_sig(i_leaf, sig_tmp, m, pk_seed, adrs)

        print("xmss_pkFromSig: root = ", end='')
        for x in root:
            print(x, end=" ")
        print()


        hp_m    = ((1 << self.hp) - 1)
        for j in range(1, self.d):
            i_leaf  =   i_tree & hp_m
            i_tree  =   i_tree >> self.hp
            adrs.set_layer_address(j)
            adrs.set_tree_address(i_tree)
            sig_tmp =   self.xmss_sign(root, sk_seed, i_leaf, pk_seed, adrs)
            sig_ht  +=  sig_tmp
            if j < self.d - 1:
                root = self.xmss_pk_from_sig(i_leaf, sig_tmp, root,
                                                pk_seed, adrs)
        return sig_ht

    def ht_verify(self, m, sig_ht, pk_seed, i_tree, i_leaf, pk_root):
        """ Algorithm 12: ht_verify(M, SIG_HT, PK.seed, idx_tree, idx_leaf,
                            PK.root). Verify a hypertree signature."""
        adrs    = ADRS()
        adrs.set_tree_address(i_tree)
        sig_tmp = sig_ht[0:(self.hp + self.len)*self.n]
        node    = self.xmss_pk_from_sig(i_leaf, sig_tmp, m, pk_seed, adrs)

        hp_m    = ((1 << self.hp) - 1)
        for j in range(1, self.d):
            i_leaf  =   i_tree & hp_m
            i_tree  =   i_tree >> self.hp
            adrs.set_layer_address(j)
            adrs.set_tree_address(i_tree)
            sig_tmp = sig_ht[j*(self.hp + self.len)*self.n:
                            (j+1)*(self.hp + self.len)*self.n]
            node = self.xmss_pk_from_sig(i_leaf, sig_tmp, node,
                                                pk_seed, adrs)

            # #if DEBUG_ENABLED
            #     printf("j = %u, ", j);
            #     printf("idx_leaf = %u, ", idx_leaf);
            #     printf("idx_tree = %u, ", idx_tree);
            #     // printf("LayerAddress = %u, ", adrs.layer);
            #     // printf("TreeAddress = %u, ",);
            #     printf("tmp_node_1: ");
            #     for (int i = 0; i < SLH_PARAM_n; i++){
            #         printf("%u ", (uint8_t)tmp_node_1[i]);
            #     }
            #     printf("\n");
            # #endif

            print("j = " + str(j), end=", ")
            print("idx_leaf = " + str(i_leaf), end=", ")
            print("idx_tree = " + str(i_tree), end=", ")
            print("tmp_node_1 = ", end='')
            for x in node:
                print(x, end=" ")
            print()
            
            
        return node == pk_root

    def fors_sk_gen(self, sk_seed, pk_seed, adrs, idx):
        """ Algorithm 13: fors_SKgen(SK.seed, PK.seed, ADRS, idx).
            Generate a FORS private-key value."""
        sk_adrs = adrs.copy()
        sk_adrs.set_type_and_clear(ADRS.FORS_PRF)
        sk_adrs.set_key_pair_address(adrs.get_key_pair_address())
        sk_adrs.set_tree_index(idx)
        return self.prf(pk_seed, sk_seed, sk_adrs)

    def fors_node(self, sk_seed, i, z, pk_seed, adrs):
        """ Algorithm 14: fors_node(SK.seed, i, z, PK.seed, ADRS).
            Compute the root of a Merkle subtree of FORS public values."""

        if z > self.a or i >= (self.k << (self.a - z)):
            return None
        if z == 0:
            sk = self.fors_sk_gen(sk_seed, pk_seed, adrs, i)
            adrs.set_tree_height(0)
            adrs.set_tree_index(i)
            node = self.h_f(pk_seed, adrs, sk)
        else:
            lnode = self.fors_node(sk_seed, 2 * i, z - 1, pk_seed, adrs)
            rnode = self.fors_node(sk_seed, 2 * i + 1, z - 1, pk_seed, adrs)
            adrs.set_tree_height(z)
            adrs.set_tree_index(i)
            node = self.h_h(pk_seed, adrs, lnode + rnode)
        return node

    def fors_sign(self, md, sk_seed, pk_seed, adrs):
        """ Algorithm 15: fors_sign(md, SK.seed, PK.seed, ADRS).
            Generate a FORS signature."""
        sig_fors = b''
        indices = self.base_2b(md, self.a, self.k)
        for i in range(self.k):
            sig_fors += self.fors_sk_gen(sk_seed, pk_seed, adrs,
                                            (i << self.a) + indices[i])
            for j in range(self.a):
                s = (indices[i] >> j) ^ 1
                sig_fors += self.fors_node(sk_seed,
                                            (i << (self.a - j)) + s, j,
                                            pk_seed, adrs)
        return sig_fors

    def fors_pk_from_sig(self, sig_fors, md, pk_seed, adrs):
        """ Algorithm 16: fors_pkFromSig(SIG_FORS, md, PK.seed, ADRS).
            Compute a FORS public key from a FORS signature."""
        def get_sk(sig_fors, i):
            return sig_fors[i*(self.a+1)*self.n:(i*(self.a+1)+1)*self.n]

        def get_auth(sig_fors, i):
            return sig_fors[(i*(self.a+1)+1)*self.n:(i+1)*(self.a+1)*self.n]

        indices = self.base_2b(md, self.a, self.k)

        print("indices = ", end='')
        for x in indices:
            print(x, end=", ")
        print()

        root = b''
        for i in range(self.k):
            sk      = get_sk(sig_fors, i)
            adrs.set_tree_height(0)
            adrs.set_tree_index((i << self.a) + indices[i])

            #print("treeindex = " + str(adrs.get_tree_index()))

            node_0  = self.h_f(pk_seed, adrs, sk)

            auth    = get_auth(sig_fors, i)


            # print("Node 0, i = " + str(i) + ": ", end='')
            # for x in node_0:
            #     print(x, end=" ")
            # print()
            # print("Auth = ", end='')
            # for x in auth:
            #     print(x, end=" ")
            # print()



            for j in range(self.a):
                auth_j = auth[j*self.n:(j+1)*self.n]
                adrs.set_tree_height(j + 1)
                if (indices[i] >> j) & 1 == 0:
                    adrs.set_tree_index(adrs.get_tree_index() // 2)
                    node_1 = self.h_h(pk_seed, adrs, node_0 + auth_j)
                else:
                    adrs.set_tree_index((adrs.get_tree_index() - 1) // 2)
                    node_1 = self.h_h(pk_seed, adrs, auth_j + node_0)
                node_0 = node_1

                # print("Node 0, j = " + str(j) + ", case = " + str((indices[i] >> j) & 1) + ", treeidx = " + str(adrs.get_tree_index()), end=': ')
                # for x in node_0:
                #     print(x, end=" ")
                # print()
                # print("Auth = ", end='')
                # for x in auth_j:
                #     print(x, end=" ")
                # print()

            root += node_0

        # print("root = ", end='')
        # for x in root:
        #     print(x, end="\t")
        # print()
            
        

        fors_pk_adrs = adrs.copy()
        fors_pk_adrs.set_type_and_clear(ADRS.FORS_ROOTS)
        fors_pk_adrs.set_key_pair_address(adrs.get_key_pair_address())
        pk  = self.h_t(pk_seed, fors_pk_adrs, root)
        return pk

    def keygen(self):
        """ Algorithm 17: slh_keygen(). Generate an SLH-DSA key pair."""

        #   The behavior is different if one performs three distinct
        #   calls to the RBG. The referenceo code does 1 call, splits it.
        seed    = self.rbg(3 * self.n)
        #seed    = [0 for i in range(3 * self.n)]        # for testing use 0 
        sk_seed = seed[0:self.n]
        sk_prf  = seed[self.n:2*self.n]
        pk_seed = seed[2*self.n:]
        adrs    = ADRS()
        adrs.set_layer_address(self.d - 1)
        pk_root = self.xmss_node(sk_seed, 0, self.hp, pk_seed, adrs)
        sk = sk_seed + sk_prf + pk_seed + pk_root
        pk = pk_seed + pk_root
        return (pk, sk)     #   Alg 17 has (sk, pk)

    def split_digest(self, digest):
        """ Helper: Lines 11-16 of Alg 18 / Lines 10-15 of Alg 19."""
        ka1     = (self.k * self.a + 7) // 8
        md      = digest[0:ka1]
        hd      = self.h // self.d
        hhd     = self.h - hd
        ka2     = ka1 + ((hhd + 7) // 8)
        i_tree  = self.to_int( digest[ka1:ka2], (hhd + 7) // 8) % (2 ** hhd)
        ka3     = ka2 + ((hd + 7) // 8)
        i_leaf  = self.to_int( digest[ka2:ka3], (hd + 7) // 8) % (2 ** hd)
        return (md, i_tree, i_leaf)

    def slh_sign(self, m, sk, randomize=True):
        """ Algorithm 18: slh_sign(M, SK). Generate an SLH-DSA signature."""
        adrs    = ADRS()
        sk_seed = sk[       0:  self.n]
        sk_prf  = sk[  self.n:2*self.n]
        pk_seed = sk[2*self.n:3*self.n]
        pk_root = sk[3*self.n:]

        opt_rand = pk_seed
        if randomize:
            opt_rand = self.rbg(self.n)

        r       = self.prf_msg(sk_prf, opt_rand, m)
        sig     = r

        digest  = self.h_msg(r, pk_seed, pk_root, m)
        (md, i_tree, i_leaf) = self.split_digest(digest)

        adrs.set_tree_address(i_tree)
        adrs.set_type_and_clear(ADRS.FORS_TREE)
        adrs.set_key_pair_address(i_leaf)

        sig_fors = self.fors_sign(md, sk_seed, pk_seed, adrs)
        sig     += sig_fors

        pk_fors = self.fors_pk_from_sig(sig_fors, md, pk_seed, adrs)

        print("pk_fors = ", end='')
        for x in pk_fors:
            print(x, end=", ")
        print()

        sig_ht  = self.ht_sign(pk_fors, sk_seed, pk_seed, i_tree, i_leaf)
        sig     += sig_ht

        return  sig

    def slh_verify(self, m, sig, pk):
        """ Algorithm 19: slh_verify(M, SIG, PK).
            Verify an SLH-DSA signature."""
        if len(sig) != self.sig_sz:
            print("SLH-DSA: Invalid signature size.")
            return False
        if len(pk) != self.pk_sz:
            print("SLH-DSA: Invalid public key size.")
            return False

        pk_seed = pk[:self.n]
        pk_root = pk[self.n:]

        adrs    = ADRS()
        r       = sig[0:self.n]
        sig_fors = sig[self.n:(1+self.k*(1+self.a))*self.n]
        sig_ht  = sig[(1 + self.k*(1 + self.a))*self.n:]

        digest  = self.h_msg(r, pk_seed, pk_root, m)
        (md, i_tree, i_leaf) = self.split_digest(digest)

        adrs.set_tree_address(i_tree)
        adrs.set_type_and_clear(ADRS.FORS_TREE)
        adrs.set_key_pair_address(i_leaf)

        pk_fors = self.fors_pk_from_sig(sig_fors, md, pk_seed, adrs)

        print("PK_fors = ", end='')
        for x in pk_fors:
            print(x, end=" ")
        print()


        return self.ht_verify(pk_fors, sig_ht, pk_seed,
                                i_tree, i_leaf, pk_root)

    #   KAT tests

    def sign(self, m, sk):
        """ Create a NIST signed message."""
        sig = self.slh_sign(m, sk)
        return sig + m

    def open(self, sm, pk):
        """ Open a NIST signed message; return None in case of failure."""
        if len(sm) < self.sig_sz:
            return None
        sig = sm[0:self.sig_sz]
        m   = sm[self.sig_sz:]
        if self.slh_verify(m, sig, pk):
            return m
        return None

#   Section 10: Table 1. SLH-DSA parameter sets

SLH_DSA_SHA2_128s   = SLH_DSA(hashname='SHA2', paramid='s',
                        n=16, h=63, d=7, hp=9, a=12, k=14, lg_w=4, m=30)
SLH_DSA_SHAKE_128s  = SLH_DSA(hashname='SHAKE', paramid='s',
                        n=16, h=63, d=7, hp=9, a=12, k=14, lg_w=4, m=30)
SLH_DSA_SHA2_128f   = SLH_DSA(hashname='SHA2', paramid='f',
                        n=16, h=66, d=22, hp=3, a=6, k=33, lg_w=4, m=34)
SLH_DSA_SHAKE_128f  = SLH_DSA(hashname='SHAKE', paramid='f',
                        n=16, h=66, d=22, hp=3, a=6, k=33, lg_w=4, m=34)

SLH_DSA_SHA2_192s   = SLH_DSA(hashname='SHA2', paramid='s',
                        n=24, h=63, d=7, hp=9, a=14, k=17, lg_w=4, m=39)
SLH_DSA_SHAKE_192s  = SLH_DSA(hashname='SHAKE', paramid='s',
                        n=24, h=63, d=7, hp=9, a=14, k=17, lg_w=4, m=39)
SLH_DSA_SHA2_192f   = SLH_DSA(hashname='SHA2', paramid='f',
                        n=24, h=66, d=22, hp=3, a=8, k=33, lg_w=4, m=42)
SLH_DSA_SHAKE_192f  = SLH_DSA(hashname='SHAKE', paramid='f',
                        n=24, h=66, d=22, hp=3, a=8, k=33, lg_w=4, m=42)

SLH_DSA_SHA2_256s   = SLH_DSA(hashname='SHA2', paramid='s',
                        n=32, h=64, d=8, hp=8, a=14, k=22, lg_w=4, m=47)
SLH_DSA_SHAKE_256s  = SLH_DSA(hashname='SHAKE', paramid='s',
                        n=32, h=64, d=8, hp=8, a=14, k=22, lg_w=4, m=47)
SLH_DSA_SHA2_256f   = SLH_DSA(hashname='SHA2', paramid='f',
                        n=32, h=68, d=17, hp=4, a=9, k=35, lg_w=4, m=49)
SLH_DSA_SHAKE_256f  = SLH_DSA(hashname='SHAKE', paramid='f',
                        n=32, h=68, d=17, hp=4, a=9, k=35, lg_w=4, m=49)

#   the order of this vector matches the order in kat hash files

SLH_DSA_ALL = [ SLH_DSA_SHA2_128f,  SLH_DSA_SHA2_128s,
                SLH_DSA_SHA2_192f,  SLH_DSA_SHA2_192s,
                SLH_DSA_SHA2_256f,  SLH_DSA_SHA2_256s,
                SLH_DSA_SHAKE_128f, SLH_DSA_SHAKE_128s,
                SLH_DSA_SHAKE_192f, SLH_DSA_SHAKE_192s,
                SLH_DSA_SHAKE_256f, SLH_DSA_SHAKE_256s, ]


import binascii

# fake rgb function that produces one char for all
def rbg(n):
    return b'\x00' * n
SLH_DSA_SHAKE_256f.set_random(rbg)

# gen keys
keys = SLH_DSA_SHAKE_256f.keygen()

# #print keys in hex
# print(binascii.hexlify(keys[1]).decode())
# print()
# print(binascii.hexlify(keys[0]).decode())  







# # sign messag; the message is the content of the msg file
# with open("msg", "rb") as f:
#     msg = f.read()

# sig = SLH_DSA_SHAKE_256f.slh_sign(msg, keys[1], False)

# # print signature in hex
# print(binascii.hexlify(sig).decode())







# # # wots_sign test
# m = b"abcdefghijklmnopqrstuvwxyz123456"
# sk_seed = b'\x00' * 32
# pk_seed = b'\x00' * 32

# myadr = ADRS()
# # myadr.set_layer_address(1)
# # myadr.set_tree_address(1)
# # myadr.set_type_and_clear(ADRS.WOTS_PRF)
# # myadr.set_key_pair_address(2)
# # myadr.set_chain_address(3)
# # myadr.set_hash_address(0)

# myadr.set_layer_address(0)
# myadr.set_tree_address(0)
# myadr.set_type_and_clear(0)
# myadr.set_key_pair_address(0)
# myadr.set_chain_address(0)
# myadr.set_hash_address(0)

# SLH_DSA_SHAKE_256f.wots_sign(m, sk_seed, pk_seed, myadr)








# # verify
with open("msg", "rb") as f:
    msg = f.read()

with open("sig", "rb") as f:
    sig = f.read()
print(SLH_DSA_SHAKE_256f.slh_verify(msg, sig, keys[0]))






