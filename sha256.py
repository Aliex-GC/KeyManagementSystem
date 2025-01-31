def to_sha256(input: bytes) -> str:
    # 定义初始哈希值
    h0 = 0x6a09e667
    h1 = 0xbb67ae85
    h2 = 0x3c6ef372
    h3 = 0xa54ff53a
    h4 = 0x510e527f
    h5 = 0x9b05688c
    h6 = 0x1f83d9ab
    h7 = 0x5be0cd19
    
    # 定义常量K
    K = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ]
    
    # 初始化哈希值
    H = [h0, h1, h2, h3, h4, h5, h6, h7]
    
    # 填充输入数据
    ml = len(input) * 8  
    input += b'\x80'
    while (len(input) * 8) % 512 != 448:
        input += b'\x00'
    
    # 添加原始消息长度（64位表示）
    input += ml.to_bytes(8, byteorder='big')
    
    # 处理消息分组
    def chunks(l, n):
        return [l[i:i+n] for i in range(0, len(l), n)]
    
    chunks512 = chunks(input, 64)
    
    # 定义辅助函数
    def rotr(x, y):
        return ((x >> y) | (x << (32 - y))) & 0xFFFFFFFF
    
    def ch(x, y, z):
        return (x & y) ^ (~x & z)
    
    def maj(x, y, z):
        return (x & y) ^ (x & z) ^ (y & z)
    
    def sigma0(x):
        return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)
    
    def sigma1(x):
        return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)
    
    def gamma0(x):
        return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3)
    
    def gamma1(x):
        return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10)
    
    # 循环处理每个消息块
    for chunk in chunks512:
        words = list(chunks(chunk, 4))
        
        # 扩展消息块
        for i in range(16, 64):
            s0 = gamma0(words[i-15][1]) + words[i-15][0]
            s1 = gamma1(words[i-2][1]) + words[i-2][0]
            words.append(((words[i-16][0] + s0 + words[i-7][0] + s1) & 0xFFFFFFFF, words[i-1][1]))

        
        # 初始化工作变量
        a, b, c, d, e, f, g, h = H
        
        # 压缩函数
        for i in range(64):
            S1 = sigma1(e) + ch(e, f, g) + h + K[i] + words[i][1]
            S0 = sigma0(a) + maj(a, b, c)
            h = g
            g = f
            f = e
            e = (d + S1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (S0 + S1) & 0xFFFFFFFF
        
        # 更新哈希值
        H = [(x + y) & 0xFFFFFFFF for x, y in zip(H, [a, b, c, d, e, f, g, h])]
    
    # 组合最终哈希值
    return ''.join(format(x, '08x') for x in H)

from Crypto.Hash import SHA256

def str_to_hash(data: str):
    # 创建SHA-256哈希对象
    hash_obj = SHA256.new()
    
    # 更新哈希对象
    hash_obj.update(data.encode('utf-8'))
    
    # 计算并返回哈希值的十六进制表示
    return hash_obj