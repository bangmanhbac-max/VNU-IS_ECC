#!/usr/bin/env python3

import sys

A = 2
B = 3
P = 97

def is_on_curve(point):
    if point is None:
        return True
    x, y = point
    return (y * y - (x * x * x + A * x + B)) % P == 0

def mod_inverse(k, p):
    if k % p == 0:
        raise ZeroDivisionError("Khong the chia cho 0 trong truong huu han")
    return pow(k, p - 2, p)

def point_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1

    x1, y1 = p1
    x2, y2 = p2

    if x1 == x2 and (y1 != y2 or y1 == 0):
        return None

    if x1 == x2 and y1 == y2:
        lmb = (3 * x1 * x1 + A) * mod_inverse(2 * y1, P) % P
    else:
        lmb = (y2 - y1) * mod_inverse(x2 - x1, P) % P

    x3 = (lmb * lmb - x1 - x2) % P
    y3 = (lmb * (x1 - x3) - y1) % P
    return (x3, y3)

def scalar_multiply(k, point):
    result = None
    addend = point

    while k > 0:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1

    return result

def main():
    print("=" * 65)
    print("   VNU-IS ECC: TOÁN HỌC ĐƯỜNG CONG ELLIPTIC")
    print("   Tác giả: Nguyễn Tuấn Minh (AIVN)")
    print(f"   Phương trình: y^2 = x^3 + {A}x + {B} (mod {P})")
    print("=" * 65)

    G = (3, 6)
    assert is_on_curve(G)
    print(f"[+] Điểm cơ sở (Generator Point G): {G}")

    print("\n--- CÁC BỘI SỐ CỦA G (k * G) ---")
    for k in range(1, 6):
        pt = scalar_multiply(k, G)
        print(f"   {k} * G = {pt}")

    print("\n--- MÔ PHỎNG TRAO ĐỔI KHÓA ECDH (ALICE & BOB) ---")
    
    priv_a = 7
    pub_A = scalar_multiply(priv_a, G)
    print(f"Alice: Private Key a = {priv_a}, Public Key A = a * G = {pub_A}")

    priv_b = 11
    pub_B = scalar_multiply(priv_b, G)
    print(f"Bob:   Private Key b = {priv_b}, Public Key B = b * G = {pub_B}")

    secret_alice = scalar_multiply(priv_a, pub_B)
    secret_bob = scalar_multiply(priv_b, pub_A)

    print(f"\nAlice tính: S_Alice = a * B = {secret_alice}")
    print(f"Bob tính:   S_Bob   = b * A = {secret_bob}")

    assert secret_alice == secret_bob
    print(f"\n[✓] Thành công: Cả hai bên đạt cùng bí mật chung S = {secret_alice}")
    print("=" * 65)

if __name__ == "__main__":
    main()
