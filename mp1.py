"""Python implementation of SHA-512 algorithm"""
	# import argparse
	# parser = argparse.ArgumentParser()
	# parser.add_argument("string", help ="encrypt input string using SHA-512 algorithm")
	# args = parser.parse_args()
	# string = args.string

"""main"""
# print(hash(string))

"""define round constants"""

K =[ 0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538, 
      0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe, 
      0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 
      0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 
      0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab, 
      0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725, 
      0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 
      0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b, 
      0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218, 
      0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 
      0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 
      0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec, 
      0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c, 
      0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6, 
      0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 
      0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
    ]

_h = [0x6a09e667f3bcc908L, 0xbb67ae8584caa73bL, 0x3c6ef372fe94f82bL, 0xa54ff53a5f1d36f1L,
     0x510e527fade682d1L, 0x9b05688c2b3e6c1fL, 0x1f83d9abfb41bd6bL, 0x5be0cd19137e2179L]
"""hashing algorithm"""




def rot_r(self, num: int, shift: int, size: int = 64):
	return ((num >> shift) | (num << size - shift)) & 0xFFFFFFFFFFFFFFFF

def S1(self, num: int):
	num  = (self.rot_r(num, 14) ^ self.rot_r(num, 18) ^ self.rot_r(num, 41))
	return num

def S0(self, num: int):
	num  = (self.rot_r(num, 28) ^ self.rot_r(num, 34) ^ self.rot_r(num, 39))
	return num

def s1(self, num: int):
	num = (self.rot_r(num, 19) ^ self.rot_r(num, 61) ^ (num >> 6))
	return num

def s0(self, num: int):
	num = (self.rot_r(num, 1) ^ self.rot_r(num, 8) ^ (num >> 7))
	return num

def ch(self, x: int, y: int, z: int):
	return (x & y) ^ (~x & z)

def maj(self, x: int, y: int, z: int):
	return (x & y) ^ (x & z) ^ (y & z)

def __init__(self, message)
	self.buffer = ''
	self.counter = 0;

	if message is not None:
			if type(message) is not str:
					raise TypeError	
	self.update(message)

def update(self, message)
		if not message
				return

		self.buffer += message
		self.counter += len(message)

		while len(self.buffer) >= 128:
			self.process(self.buffer[:128])
			self.buffer = self.buffer[128:]

def process(self, block):
		w = [0]*80
		w[0:16] = struct.unpack('16Q', block)

		for i in range(16,80):
				sigma0 = s0(w[i-15])
				sigma1 = s1(w[i-2])
				w[i] = (w[i-16] + sigma0 + w[i-7] + sigma1) & 0xFFFFFFFFFFFFFFFF
		a,b,c,d,e,f,g,h = self._h

		for i in range(80)
				Sigma0 = S0(a)
				maj0 = maj(a,b,c)
				temp2 = Sigma0 + maj
				Sigma1 = S1(e)
				ch0 = ch(e,f,g) 
				temp1 = h + s1 + ch + self.K[i] + w[i]

				h = g
				g = f
				f = e
				e = (d + temp1) & 0xFFFFFFFFFFFFFFFF
				d = c
				c = b
				b = a
				a = (temp1 + temp2) & 0xFFFFFFFFFFFFFFFF

		self._h = [(x+y) & 0xFFFFFFFFFFFFFFFF for x,y in zip(self._h, [a,b,c,d,e,f,g,h])]
def digest(self):
	i = self.counter & 0x7F
	length = struct.pack('!Q', self._counter<<3)

	if i < 112:
		pad = 111 - i
	else
		pad = 239 - i

	self2 =  copy.deepcopy(self)
	self2.update('\x80'+('\x00'*(pad+8))+length)
	return ''.join([struct.pack('!Q', j) for j in self2._h[:self.8]])