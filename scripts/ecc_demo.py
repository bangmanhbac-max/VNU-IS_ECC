#!/usr/bin/env python3
"""
ecc_demo.py - Bản trình diễn toán học cốt lõi của Mật mã Đường cong Elliptic (ECC)
Sử dụng thư viện chuẩn của Python để minh họa trực quan:
1. Trường hữu hạn và Phép toán nhóm trên đường cong Weierstrass: y^2 = x^3 + ax + b (mod p)
2. Phép cộng điểm (Point Addition) & Phép nhân đôi điểm (Point Doubling)
3. Phép nhân vô hướng (Scalar Multiplication - Double-and-Add)
4. Trao đổi khóa Diffie-Hellman đường cong Elliptic (ECDH)
"""

import sys

# Định nghĩa một đường cong Elliptic đồ chơi (Toy Curve) trên trường hữu hạn F_p để kiểm chứng số học
# y^2 = x^3 + 2x + 3 (mod 97)
A = 2
B = 3
P = 97  # Số nguyên tố p

def is_on_curve(point):
    """Kiểm tra điểm (x, y) có nằm trên đường cong hay không."""
    if point is None:
        return True  # Điểm vô cực O
    x, y = point
    return (y * y - (x * x * x + A * x + B)) % P == 0

def mod_inverse(k, p):
    """Nghịch đảo modulo k^-1 mod p bằng thuật toán Euclid mở rộng."""
    if k % p == 0:
        raise ZeroDivisionError("Khong the chia cho 0 trong truong huu han")
    return pow(k, p - 2, p)  # Theo định lý nhỏ Fermat (p là số nguyên tố)

def point_add(p1, p2):
    """Cộng hai điểm P1 + P2 trên đường cong Elliptic."""
    if p1 is None:
        return p2
    if p2 is None:
        return p1

    x1, y1 = p1
    x2, y2 = p2

    # P + (-P) = O (Điểm vô cực)
    if x1 == x2 and (y1 != y2 or y1 == 0):
        return None

    # Nhân đôi điểm (Point Doubling): P1 == P2
    if x1 == x2 and y1 == y2:
        lmb = (3 * x1 * x1 + A) * mod_inverse(2 * y1, P) % P
    else:
        # Cộng hai điểm phân biệt: P1 != P2
        lmb = (y2 - y1) * mod_inverse(x2 - x1, P) % P

    x3 = (lmb * lmb - x1 - x2) % P
    y3 = (lmb * (x1 - x3) - y1) % P
    return (x3, y3)

def scalar_multiply(k, point):
    """Nhân vô hướng k * P bằng giải thuật Double-and-Add (O(log k))."""
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
    print("   TOÁN HỌC ĐƯỜNG CONG ELLIPTIC - MINH HỌA TRỰC QUAN")
    print(f"   Phương trình: y^2 = x^3 + {A}x + {B} (mod {P})")
    print("=" * 65)

    # Chọn một điểm sinh (Generator Point G)
    G = (3, 6)
    assert is_on_curve(G), "Điểm G phải thuộc đường cong!"
    print(f"[+] Điểm cơ sở (Generator Point G): {G}")

    # Sinh một số điểm nhóm qua phép nhân vô hướng
    print("\n--- CÁC BỘI SỐ CỦA G (k * G) ---")
    for k in range(1, 6):
        pt = scalar_multiply(k, G)
        print(f"   {k} * G = {pt}")

    # Minh họa bắt tay trao đổi khóa ECDH giữa Alice và Bob
    print("\n--- MÔ PHỎNG TRAO ĐỔI KHÓA ECDH (ALICE & BOB) ---")
    
    # 1. Alice chọn khóa riêng a ngẫu nhiên
    priv_a = 7
    pub_A = scalar_multiply(priv_a, G)
    print(f"Alice: Private Key a = {priv_a}, Public Key A = a * G = {pub_A}")

    # 2. Bob chọn khóa riêng b ngẫu nhiên
    priv_b = 11
    pub_B = scalar_multiply(priv_b, G)
    print(f"Bob:   Private Key b = {priv_b}, Public Key B = b * G = {pub_B}")

    # 3. Hai bên trao đổi khóa công khai và tính Shared Secret
    secret_alice = scalar_multiply(priv_a, pub_B)  # a * B = a * (b * G)
    secret_bob = scalar_multiply(priv_b, pub_A)    # b * A = b * (a * G)

    print(f"\nAlice tính: S_Alice = a * B = {secret_alice}")
    print(f"Bob tính:   S_Bob   = b * A = {secret_bob}")

    assert secret_alice == secret_bob, "Bí mật chung phải giống nhau!"
    print(f"\n[✓] Thành công: Cả hai bên đạt cùng bí mật chung S = {secret_alice}")
    print(f"    Kẻ tấn công chỉ biết G={G}, A={pub_A}, B={pub_B} nhưng KHÔNG THỂ")
    print(f"    tìm ra a, b trong thời gian thực do Bài toán Logarit Rời rạc (ECDLP)!")
    print("=" * 65)

if __name__ == "__main__":
    main()
